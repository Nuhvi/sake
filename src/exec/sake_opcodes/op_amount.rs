//! OP_AMOUNT [BIP ??](TBD)

use bitcoin::{Opcode, ScriptBuf, opcodes::all::OP_RETURN_228};

use crate::{Exec, exec::ExecError};

pub(crate) const OP_CODE: Opcode = OP_RETURN_228;

pub const OP_AMOUNT_CURRENT_INPUT_SELECTOR: i32 = 0;
pub fn op_amount_input_selector(input_index: usize) -> i32 {
    -input_index.cast_signed() as i32 - 1
}
pub fn op_amount_output_selector(output_index: usize) -> i32 {
    output_index as i32 + 1
}

#[allow(non_snake_case)]
pub fn OP_AMOUNT() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CODE.to_u8()])
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_amount(&mut self) -> Result<(), ExecError> {
        let inout_index = self.stack.popnum()?;

        let amount = match inout_index {
            0 => self
                .prevouts
                .get(self.input_idx)
                .map(|txout| txout.value)
                .expect("number of inputs and prevouts checked earlier"),
            i64::MIN..=-1_i64 => self
                .prevouts
                .get(inout_index.unsigned_abs() as usize - 1)
                .map(|txout| txout.value)
                .ok_or(ExecError::OpAmountError(
                    OpAmountError::OutOfBoundInputIndex,
                ))?,
            1_i64..=i64::MAX => self
                .sighashcache
                .transaction()
                .output
                .get(inout_index as usize - 1)
                .map(|out| out.value)
                .ok_or(ExecError::OpAmountError(
                    OpAmountError::OutOfBoundOutputIndex,
                ))?,
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
    OutOfBoundInputIndex,
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

    use bitcoin::{ScriptBuf, Transaction, TxOut, sighash::SighashCache};
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

        let mut exec = Exec::new(
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
