use bitcoin::{
    Amount, ScriptBuf, TxOut, VarInt,
    consensus::{Decodable, Encodable},
    opcodes::all::OP_RETURN,
    script::{Instruction, PushBytesBuf},
};
use std::io::{Cursor, Read}; // Added necessary imports

const PREFIX: &[u8] = b"SAKE";
pub(crate) const MAX_SUPPORTED_VERSION_VERSION: u8 = 0;

pub trait SakeWitnessCarrier {
    fn sake_witness_carrier(stacks: &[(usize, Vec<Vec<u8>>)]) -> TxOut;
    #[allow(clippy::type_complexity)]
    fn parse_witness_stacks(&self) -> Result<Vec<(usize, Vec<Vec<u8>>)>, WitnessCarrierError>;
}

impl SakeWitnessCarrier for TxOut {
    /// Generates a SAKE witness carriers scriptPubkey from multiple script witness stacks
    fn sake_witness_carrier(stacks: &[(usize, Vec<Vec<u8>>)]) -> TxOut {
        let mut bytes = vec![];

        // 1. "SAKE" (4 bytes)
        bytes.extend_from_slice(PREFIX);

        // 2. Version (1 byte)
        bytes.push(MAX_SUPPORTED_VERSION_VERSION);

        // Stacks
        for (input_index, stack) in stacks {
            // 4.1
            VarInt(*input_index as u64)
                .consensus_encode(&mut bytes)
                .expect("write failed");

            // 4.2 Stack len
            VarInt(stack.len() as u64)
                .consensus_encode(&mut bytes)
                .expect("write failed");

            // 4.3 Stack elements
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

        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(data),
        }
    }

    /// Parses witness stacks from an OP_RETURN script.
    ///
    /// **Format:** OP_RETURN <push: SAKE | Version | [I Input Index (VarInt)] | [N elements (VarInt)] | [E Element len | data]...>
    fn parse_witness_stacks(&self) -> Result<Vec<(usize, Vec<Vec<u8>>)>, WitnessCarrierError> {
        let mut instructions = self.script_pubkey.instructions();

        match instructions.next() {
            Some(Ok(Instruction::Op(OP_RETURN))) => {}
            _ => return Err(WitnessCarrierError::NotOpReturn),
        }

        let payload = match instructions.next() {
            Some(Ok(Instruction::PushBytes(bytes))) => bytes.as_bytes(),
            _ => return Err(WitnessCarrierError::MissingPrefix),
        };

        // Use a Cursor to read the payload, leveraging bitcoin::consensus::Decodable
        let mut cursor = Cursor::new(payload);

        // --- Parse Payload Header (Prefix and Version) ---

        let mut prefix_data = [0u8; PREFIX.len()];
        if cursor.read_exact(&mut prefix_data).is_err() || prefix_data != *PREFIX {
            return Err(WitnessCarrierError::MissingPrefix);
        }

        let mut version_data = [0u8; 1];
        if cursor.read_exact(&mut version_data).is_err() {
            return Err(WitnessCarrierError::MissingVersion);
        }
        if version_data[0] > MAX_SUPPORTED_VERSION_VERSION {
            return Err(WitnessCarrierError::UnsupportedVersion);
        }

        // --- Parse Stacks ---

        let mut witness_stacks = Vec::new();

        // Check if there is more data to read (cursor position < payload length)
        while (cursor.position() as usize) < payload.len() {
            let input_index = match VarInt::consensus_decode(&mut cursor) {
                Ok(v) => v.0 as usize,
                Err(_) => return Err(WitnessCarrierError::InvalidInputIndex),
            };
            let n = match VarInt::consensus_decode(&mut cursor) {
                Ok(v) => v.0 as usize,
                Err(_) => return Err(WitnessCarrierError::InvalidElementsCount),
            };

            let mut stack = Vec::with_capacity(n);

            for _ in 0..n {
                let element_len = match VarInt::consensus_decode(&mut cursor) {
                    Ok(v) => v.0 as usize,
                    Err(_) => return Err(WitnessCarrierError::InvalidElement),
                };

                let mut element = vec![0u8; element_len];
                if cursor.read_exact(&mut element).is_err() {
                    return Err(WitnessCarrierError::InvalidElement);
                }

                stack.push(element);
            }

            witness_stacks.push((input_index, stack));
        }

        Ok(witness_stacks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessCarrierError {
    NotOpReturn,
    MissingPrefix,
    MissingVersion,
    UnsupportedVersion,
    InvalidStacksCount,
    InvalidInputIndex,
    InvalidElementsCount,
    InvalidElement,
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
        ) -> Vec<(usize,Vec<Vec<u8>>)> {
            stacks.into_iter().enumerate().collect()
        }
    }

    // The fuzz test function
    proptest! {
        #[test]
        fn prop_round_trip_stacks(stacks in arb_stacks()) {
            let witness_carrier = TxOut::sake_witness_carrier(&stacks);

            let parsed = match witness_carrier.parse_witness_stacks() {
                Ok(p) => p,
                Err(e) => {
                    panic!("Parsing failed unexpectedly: {e:?} for stacks: {stacks:?}");
                }
            };

            assert_eq!(parsed, stacks, "Round-trip failed: original != parsed");
        }
    }
}
