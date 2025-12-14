use bitcoin::{ScriptBuf, Transaction, TxOut, opcodes::all::OP_RETURN, script::Instruction};

use crate::exec::{Error, Exec};

pub mod error;
pub mod exec;
pub mod stack;

// TODO: Add a helper function to convert Witness script to OP_RETURN output

/// Prefix for SAKE scripts: OP_PUSHBYTES_4 + "SAKE" (ASCII)
/// Corresponds to script: `OP_PUSHBYTES_4 53414b45`
const SAKE_SCRIPT_PREFIX: [u8; 5] = [0x04, 0x53, 0x41, 0x4B, 0x45]; // 4, 'S', 'A', 'K', 'E'

/// Validates SAKE scripts in a transaction.
pub fn validate(tx: &Transaction, prevouts: &[TxOut], scripts: &[ScriptBuf]) -> Result<(), Error> {
    // Step 1: Collect indices of SAKE inputs
    let sake_input_indices: Vec<usize> = scripts
        .iter()
        .enumerate()
        .filter(|(_, script)| script.as_bytes().starts_with(&SAKE_SCRIPT_PREFIX))
        .map(|(i, _)| i)
        .collect();

    if sake_input_indices.is_empty() {
        return Err(Error::NoRelevantInputsToValidate);
    }

    // Step 2: Extract witness stacks from the last output if it's OP_RETURN
    let witness_stacks = if let Some(last_output) = tx.output.last() {
        parse_sake_witnesses_from_opreturn(&last_output.script_pubkey)?
    } else {
        vec![]
    };

    // Step 3: Validate count
    if witness_stacks.len() != sake_input_indices.len() {
        return Err(Error::WitnessCountMismatch {
            expected: sake_input_indices.len(),
            found: witness_stacks.len(),
        });
    }

    // Step 4: Execute each SAKE script with its witness
    for (idx, &input_idx) in sake_input_indices.iter().enumerate() {
        let witness_stack = &witness_stacks[idx];
        let script = &scripts[input_idx];

        let mut exec = Exec::new(
            tx,
            prevouts.to_vec(),
            input_idx,
            script.clone(),
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
                        return Err(Error::ScriptVerificationFailed(input_idx));
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
