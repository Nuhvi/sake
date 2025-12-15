use bitcoin::{ScriptBuf, Transaction, TxOut, sighash::SighashCache};

mod error;
mod exec;
mod script_witness;
mod stack;

pub use crate::exec::Error;
pub use exec::Exec;

/// Validates SAKE scripts in a transaction.
///
/// - `tx`: The transaction (used to calculate the sighash) and the last output contains the script witnesses as an OP_RETURN
/// - `prevouts`: All the previous [TxOut]s for all the inputs (used to calculate the sighash).
/// - `scripts` : Tuples of (`input index`, `ScriptBuf`) for the inputs to evaluate.
///     - `input_index`: used in sighash calculation.
///     - `ScriptBuf`: locking script for this input, evaluated with the respective script witness defcoded from the last [TxOut] (`OP_RETURN`) in the `tx`.
pub fn validate(
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[(usize, ScriptBuf)],
) -> Result<(), Error> {
    if inputs.is_empty() {
        return Ok(());
    }

    // Step 1: Extract witness stacks from the last output if it's OP_RETURN
    let witness_stacks = if let Some(last_output) = tx.output.last() {
        script_witness::parse(&last_output.script_pubkey).map_err(Error::InvalidScriptWitness)?
    } else {
        vec![]
    };

    // Step 2: Validate count
    if witness_stacks.len() != inputs.len() {
        return Err(Error::WitnessCountMismatch {
            expected: inputs.len(),
            found: witness_stacks.len(),
        });
    }

    let mut sighashcache = SighashCache::new(tx.clone());

    // Step 3: Execute each input script with its witness
    for ((input_idx, script), witness_stack) in inputs.iter().zip(witness_stacks) {
        let mut exec = Exec::new(
            &mut sighashcache,
            prevouts,
            *input_idx,
            script,
            witness_stack.clone(),
        )?;

        loop {
            match exec.exec_next() {
                Ok(_) => continue,
                Err(exec_result) => {
                    if let Some(err) = &exec_result.error {
                        //  TODO: log stack

                        // Return execution error
                        return Err(Error::Exec(err.clone()));
                    } else if !exec_result.success {
                        return Err(Error::ScriptVerificationFailed(*input_idx));
                    }

                    break; // Script finished successfully
                }
            }
        }
    }

    Ok(())
}
