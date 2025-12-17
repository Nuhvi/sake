use bitcoin::{
    ScriptBuf, VarInt,
    consensus::{Decodable, Encodable},
    opcodes::all::OP_RETURN,
    script::{Instruction, PushBytesBuf},
};
use std::io::{Cursor, Read}; // Added necessary imports

use crate::error::ScriptWitnessError;

const PREFIX: &[u8] = b"SAKE";
const EXPECTED_VERSION: u8 = 0;

/// Parses witness stacks from an OP_RETURN script.
///
/// **Format:** OP_RETURN <push: SAKE | Version | K stacks | [N elements (VarInt)] | [E Element len | data]...>
pub fn parse(script: &ScriptBuf) -> Result<Vec<Vec<Vec<u8>>>, ScriptWitnessError> {
    let mut instructions = script.instructions();

    match instructions.next() {
        Some(Ok(Instruction::Op(OP_RETURN))) => {}
        _ => return Err(ScriptWitnessError::NotOpReturn),
    }

    let payload = match instructions.next() {
        Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
        _ => return Err(ScriptWitnessError::MissingPrefix),
    };

    // Use a Cursor to read the payload, leveraging bitcoin::consensus::Decodable
    let mut cursor = Cursor::new(payload);

    // --- Parse Payload Header (Prefix and Version) ---

    let mut prefix_data = [0u8; PREFIX.len()];
    if cursor.read_exact(&mut prefix_data).is_err() || prefix_data != *PREFIX {
        return Err(ScriptWitnessError::MissingPrefix);
    }

    let mut version_data = [0u8; 1];
    if cursor.read_exact(&mut version_data).is_err() || version_data[0] != EXPECTED_VERSION {
        return Err(ScriptWitnessError::WrongVersion);
    }

    // --- Parse Stacks Count ---

    let k = match VarInt::consensus_decode(&mut cursor) {
        Ok(v) => v.0 as usize,
        Err(_) => return Err(ScriptWitnessError::InvalidStacksCount),
    };

    let mut witness_stacks = Vec::with_capacity(k);

    // --- Parse Concatenated Stack Data ---

    for _ in 0..k {
        let n = match VarInt::consensus_decode(&mut cursor) {
            Ok(v) => v.0 as usize,
            Err(_) => return Err(ScriptWitnessError::InvalidElementsCount),
        };

        let mut stack = Vec::with_capacity(n);

        for _ in 0..n {
            let element_len = match VarInt::consensus_decode(&mut cursor) {
                Ok(v) => v.0 as usize,
                Err(_) => return Err(ScriptWitnessError::InvalidElement),
            };

            let mut element = vec![0u8; element_len];
            if cursor.read_exact(&mut element).is_err() {
                return Err(ScriptWitnessError::InvalidElement);
            }

            stack.push(element);
        }

        witness_stacks.push(stack);
    }

    Ok(witness_stacks)
}

pub trait SakeWitnessCarrier {
    fn new_sake_witness_carrier(stacks: &[Vec<Vec<u8>>]) -> Self;
}

impl SakeWitnessCarrier for ScriptBuf {
    /// Generates a SAKE witness carriers scriptPubkey from multiple script witness stacks
    fn new_sake_witness_carrier(stacks: &[Vec<Vec<u8>>]) -> Self {
        let mut bytes = vec![];

        // 1. "SAKE" (4 bytes)
        bytes.extend_from_slice(PREFIX);

        // 2. Version (1 byte)
        bytes.push(EXPECTED_VERSION);

        // 3. Stacks count
        VarInt(stacks.len() as u64)
            .consensus_encode(&mut bytes)
            .expect("write failed");

        // 4. Stack items
        for stack in stacks {
            // 4.1 Stack len
            VarInt(stack.len() as u64)
                .consensus_encode(&mut bytes)
                .expect("write failed");

            // 3.2 Stack element
            for element in stack {
                VarInt(element.len() as u64)
                    .consensus_encode(&mut bytes)
                    .expect("write failed");
                bytes.extend_from_slice(element);
            }
        }

        let mut data = PushBytesBuf::new();
        data.extend_from_slice(&bytes)
            .expect("Script witnesses too long");

        ScriptBuf::new_op_return(data)
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    // Define the constraints for the generated test case data.
    prop_compose! {
        // Generate a single byte vector (the innermost element)
        fn arb_element()(
            len in 0..=500usize,
            bytes: Vec<u8>,
        ) -> Vec<u8> {
            bytes.into_iter().take(len).collect()
        }
    }

    prop_compose! {
        // Generate an entire Witness Stacks structure: Vec<Vec<Vec<u8>>>
        fn arb_stacks()(
            num_stacks in 0..=5usize,
        ) (
            stacks in proptest::collection::vec(
                proptest::collection::vec(arb_element(), 0..=10),
                num_stacks
            )
        ) -> Vec<Vec<Vec<u8>>> {
            stacks
        }
    }

    // The fuzz test function
    proptest! {
        #[test]
        fn prop_round_trip_stacks(stacks in arb_stacks()) {
            let encoded = ScriptBuf::new_sake_witness_carrier(&stacks);

            let parsed = match parse(&encoded) {
                Ok(p) => p,
                Err(e) => {
                    panic!("Parsing failed unexpectedly: {e:?} for stacks: {stacks:?}");
                }
            };

            assert_eq!(parsed, stacks, "Round-trip failed: original != parsed");
        }
    }
}
