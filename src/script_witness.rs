use bitcoin::{ScriptBuf, opcodes::all::OP_RETURN, script::Instruction};

use crate::error::ScriptWitnessError;

const EXPECTED_VERSION: &[u8] = &[0];

/// Parses witness stacks from an OP_RETURN script.
/// Format:
/// OP_RETURN
///   <push: b"SAKE">
///   <push: <version>>
///   <push: [n0, n1, ..., nk]> // one byte per stack: item count for stack i
///   <push: stack0_data0>
///   <push: stack0_data1>
///   <push: stack1_data0>
///   <push: stack1_data1>
///   ...
pub fn parse(script: &ScriptBuf) -> Result<Vec<Vec<Vec<u8>>>, ScriptWitnessError> {
    let mut instructions = script.instructions();

    // 1. OP_RETURN
    match instructions.next() {
        Some(Ok(Instruction::Op(OP_RETURN))) => {}
        _ => return Err(ScriptWitnessError::NotOpReturn),
    }

    // 2. "SAKE"
    match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == b"SAKE" => {}
        _ => return Err(ScriptWitnessError::MissingPrefix),
    }

    // 3. Version (2 bytes, big-endian)
    match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) if bytes.as_bytes() == EXPECTED_VERSION => {}
        _ => return Err(ScriptWitnessError::WrongVersion),
    }

    // 4. Stack item counts: one u8 per stack
    let bytes = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
        _ => return Err(ScriptWitnessError::InvalidElementsCount),
    };

    let mut stack_items_counts = vec![];

    for byte in bytes {
        if *byte > 252 {
            // TODO: support variable integer
            return Err(ScriptWitnessError::InvalidElementsCount);
        }

        stack_items_counts.push(byte)
    }

    // 5. Parse each witness stack (must be exactly `expected_stack_count` pushes)
    let mut witness_stacks = Vec::with_capacity(stack_items_counts.len());

    for expected_items_count in stack_items_counts.iter() {
        let mut stack = vec![];

        for _ in 0..**expected_items_count as usize {
            let x = instructions.next();
            dbg!((&x, expected_items_count));
            let element = match x {
                Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
                Some(Ok(Instruction::Op(opcode))) => &[opcode.to_u8()],
                _ => return Err(ScriptWitnessError::InvalidStackElement),
            };
            dbg!((&x, expected_items_count));

            stack.push(element.to_vec());
        }

        witness_stacks.push(stack);
    }

    dbg!(&witness_stacks);

    // Ensure no extra instructions
    if instructions.next().is_some() {
        return Err(ScriptWitnessError::InvalidElementsCount);
    }

    Ok(witness_stacks)
}
