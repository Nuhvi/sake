//! OP_AMOUNT [BIP-pr#2069](https://github.com/bitcoin/bips/pull/2069/files#bip-op-amount.md)

use bitcoin::{Opcode, ScriptBuf, opcodes::all::OP_RETURN_228};

use crate::{Exec, exec::ExecError};

pub(crate) const OP_CODE: Opcode = OP_RETURN_228;

/// Returns the `OP_AMOUNT` opcode as a one-byte script.
///
/// The opcode pushes the amount as a signed 64-bit integer. Numeric opcodes
/// read at most four bytes, so a script must compare larger amounts with
/// `OP_EQUAL` on the full encoding.
#[allow(non_snake_case)]
#[must_use]
pub fn OP_AMOUNT() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CODE.to_u8()])
}

/// Selects the amount of the current input.
pub const OP_AMOUNT_CURRENT_INPUT_SELECTOR: i64 = 0;

/// Returns the selector for the amount of input `input_index`.
///
/// Input selectors are negative: input `n` uses `-(n + 1)`. Values above
/// `i64::MAX` saturate, so they select an input that is out of bounds.
#[must_use]
pub fn op_amount_input_selector(input_index: usize) -> i64 {
    let index = i64::try_from(input_index).unwrap_or(i64::MAX);
    -index - 1
}

/// Returns the selector for the amount of output `output_index`.
///
/// Output selectors are positive: output `n` uses `n + 1`. Values above
/// `i64::MAX` saturate, so they select an output that is out of bounds.
#[must_use]
pub fn op_amount_output_selector(output_index: usize) -> i64 {
    let index = i64::try_from(output_index).unwrap_or(i64::MAX);
    index.saturating_add(1)
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_amount(&mut self) -> Result<(), ExecError> {
        let selector = self.stack.popnum()?;

        let amount = match selector {
            OP_AMOUNT_CURRENT_INPUT_SELECTOR => self
                .prevouts
                .get(self.input_idx)
                .map(|txout| txout.value)
                .ok_or(ExecError::OpAmountError(
                    OpAmountError::OutOfBoundInputIndex,
                ))?,
            i64::MIN..=-1_i64 => {
                let index = usize::try_from(selector.unsigned_abs())
                    .ok()
                    .and_then(|index| index.checked_sub(1))
                    .ok_or(ExecError::OpAmountError(
                        OpAmountError::OutOfBoundInputIndex,
                    ))?;
                self.prevouts.get(index).map(|txout| txout.value).ok_or(
                    ExecError::OpAmountError(OpAmountError::OutOfBoundInputIndex),
                )?
            }
            1_i64..=i64::MAX => {
                let index = usize::try_from(selector)
                    .ok()
                    .and_then(|index| index.checked_sub(1))
                    .ok_or(ExecError::OpAmountError(
                        OpAmountError::OutOfBoundOutputIndex,
                    ))?;
                self.sighashcache
                    .transaction()
                    .output
                    .get(index)
                    .map(|out| out.value)
                    .ok_or(ExecError::OpAmountError(
                        OpAmountError::OutOfBoundOutputIndex,
                    ))?
            }
        }
        .to_sat()
        .cast_signed();

        self.stack.pushnum(amount);

        Ok(())
    }
}

/// Error specific to OP_AMOUNT
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpAmountError {
    /// The selector points to an input that does not exist.
    OutOfBoundInputIndex,
    /// The selector points to an output that does not exist.
    OutOfBoundOutputIndex,
}

#[cfg(test)]
mod tests {
    use crate::{
        OP_AMOUNT,
        exec::{Exec, ExecError, op_amount::OP_AMOUNT_CURRENT_INPUT_SELECTOR},
        op_amount_input_selector, op_amount_output_selector,
        tests::dummy_tx,
    };

    use bitcoin::{ScriptBuf, Transaction, TxOut, key::Secp256k1, sighash::SighashCache};
    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    fn verify(
        sighashcache: &mut SighashCache<Transaction>,
        prevouts: &[TxOut],
        input_index: usize,
        script: &ScriptBuf,
        expected_error: Option<ExecError>,
    ) {
        let witness = vec![];
        let secp = Secp256k1::new();

        let mut exec = Exec::new(
            &secp,
            sighashcache,
            prevouts,
            input_index,
            // The basic script
            script,
            witness,
        )
        .unwrap();

        loop {
            match exec.exec_next() {
                Ok(_) => continue,
                Err(err) => {
                    if let Some(expected_error) = expected_error {
                        assert_eq!(err, expected_error);
                    } else {
                        assert_eq!(err, ExecError::NoMoreInstructions { success: true });
                    }
                    break;
                }
            }
        }
    }

    #[test]
    fn test_op_current_input_amount() {
        let (tx, prevouts) = dummy_tx();

        let mut sighashcache = SighashCache::new(tx);

        for (input_index, prevout) in prevouts.iter().enumerate() {
            let script = script! {
                <OP_AMOUNT_CURRENT_INPUT_SELECTOR>
                OP_AMOUNT
                <prevout.value.to_sat().cast_signed()>
                OP_GREATERTHANOREQUAL
            };

            verify(&mut sighashcache, &prevouts, input_index, &script, None);
        }
    }

    #[test]
    fn test_op_input_amount() {
        let (tx, prevouts) = dummy_tx();

        let mut sighashcache = SighashCache::new(tx);

        for (input_index, prevout) in prevouts.iter().enumerate() {
            let script = script! {
                <op_amount_input_selector(input_index)>
                OP_AMOUNT
                <prevout.value.to_sat().cast_signed()>
                OP_GREATERTHANOREQUAL
            };

            verify(&mut sighashcache, &prevouts, input_index, &script, None);
        }
    }

    #[test]
    fn test_op_amount_out_of_bound_input() {
        let (tx, prevouts) = dummy_tx();

        let mut sighashcache = SighashCache::new(tx);

        verify(
            &mut sighashcache,
            &prevouts,
            0,
            &script! {
                <op_amount_input_selector(prevouts.len())>
                OP_AMOUNT
                <prevouts.last().unwrap().value.to_sat().cast_signed()>
                OP_GREATERTHANOREQUAL
            },
            Some(ExecError::OpAmountError(
                crate::OpAmountError::OutOfBoundInputIndex,
            )),
        );
    }

    #[test]
    fn test_op_output_amount() {
        let (tx, prevouts) = dummy_tx();

        let mut sighashcache = SighashCache::new(tx.clone());

        for (output_index, output) in tx.output.iter().enumerate() {
            let script = script! {
                <op_amount_output_selector(output_index)>
                OP_AMOUNT
                <output.value.to_sat().cast_signed()>
                OP_GREATERTHANOREQUAL
            };

            verify(&mut sighashcache, &prevouts, 0, &script, None);
        }
    }

    #[test]
    fn test_op_amount_out_of_bound_output() {
        let (tx, prevouts) = dummy_tx();

        let mut sighashcache = SighashCache::new(tx.clone());

        verify(
            &mut sighashcache,
            &prevouts,
            0,
            &script! {
                <op_amount_output_selector(tx.output.len())>
                OP_AMOUNT
                <tx.output.last().unwrap().value.to_sat().cast_signed()>
                OP_GREATERTHANOREQUAL
            },
            Some(ExecError::OpAmountError(
                crate::OpAmountError::OutOfBoundOutputIndex,
            )),
        );
    }
}
