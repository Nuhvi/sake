use bitcoin::{
    ScriptBuf, Transaction, TxOut, opcodes::all::OP_RETURN, script::Instruction,
    sighash::SighashCache,
};

use crate::exec::{Error, Exec};

pub mod error;
pub mod exec;
pub mod stack;

// TODO: Add a helper function to convert Witness script to OP_RETURN output
// TODO: use pushdata instead of pushbytes

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
        parse_sake_witnesses_from_opreturn(&last_output.script_pubkey)?
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

/// Parses witness stacks from an OP_RETURN script.
/// Expects: OP_RETURN <pushdata: stack0> <pushdata: stack1> ...
/// Each pushdata is a serialized witness stack:
/// [num_items: u8][len0: u8][data0]...[lenN: u8][dataN]
fn parse_sake_witnesses_from_opreturn(script: &ScriptBuf) -> Result<Vec<Vec<Vec<u8>>>, Error> {
    let mut instructions = script.instructions();

    // First instruction must be OP_RETURN
    if !matches!(
        instructions.next().map(|res| res.map(|inst| inst.opcode())),
        Some(Ok(Some(OP_RETURN)))
    ) {
        // Not OP_RETURN
        return Err(Error::InvalidWitnessOutputFormat);
    }

    let mut witness_stacks = Vec::new();

    // Parse each subsequent push as a witness stack
    for instruction in instructions {
        let data = match instruction {
            Ok(Instruction::PushBytes(pb)) => pb.as_bytes(),
            Ok(_) => return Err(Error::InvalidWitnessOutputFormat), // Non-push after OP_RETURN
            Err(_) => return Err(Error::InvalidWitnessOutputFormat),
        };

        let stack = deserialize_witness_stack(data)?;
        witness_stacks.push(stack);
    }

    Ok(witness_stacks)
}

/// Deserializes a single witness stack from compact format:
/// [num_items: u8][len0: u8][data0][len1: u8][data1]...
fn deserialize_witness_stack(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    if data.is_empty() {
        return Ok(vec![]);
    }

    let num_items = data[0] as usize;
    if num_items == 0 {
        return Ok(vec![]);
    }

    let mut stack = Vec::with_capacity(num_items);
    let mut offset = 1;

    for _ in 0..num_items {
        if offset >= data.len() {
            return Err(Error::InvalidWitnessEncoding);
        }

        let item_len = data[offset] as usize;
        offset += 1;

        if offset + item_len > data.len() {
            return Err(Error::InvalidWitnessEncoding);
        }

        stack.push(data[offset..offset + item_len].to_vec());
        offset += item_len;
    }

    // Allow trailing bytes? Better to be strict.
    if offset != data.len() {
        return Err(Error::InvalidWitnessEncoding);
    }

    Ok(stack)
}
