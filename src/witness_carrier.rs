use bitcoin::{
    Amount, ScriptBuf, TxOut, VarInt,
    consensus::Decodable,
    opcodes::all::OP_RETURN,
    script::{Instruction, PushBytesBuf},
};
use std::io::{Cursor, Read};

const PREFIX: &[u8] = b"SAKE";
pub(crate) const MAX_SUPPORTED_VERSION: u8 = 0;
/// BIP-342 initial stack element limit.
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// BIP-342 initial stack element count limit.
const MAX_STACK_SIZE: usize = 1000;

/// Builds and parses SAKE witness carrier outputs.
pub trait SakeWitnessCarrier {
    /// Builds a SAKE witness carrier.
    ///
    /// Returns an error for stacks that the BIP-342 initial stack limits
    /// would reject.
    ///
    /// Returns [`WitnessCarrierError::TooManyElements`] when a stack has more
    /// than 1000 elements, [`WitnessCarrierError::InvalidElement`] when an
    /// element is larger than 520 bytes, and
    /// [`WitnessCarrierError::PayloadTooLong`] when the payload exceeds the
    /// `PushBytes` encoding limit.
    fn sake_witness_carrier(stacks: &[(usize, Vec<Vec<u8>>)])
    -> Result<TxOut, WitnessCarrierError>;

    /// Parses the witness stacks from an `OP_RETURN` output.
    ///
    /// **Format:** OP_RETURN <push: SAKE | Version | [I Input Index (VarInt)] | [N elements (VarInt)] | [E Element len | data]...>
    #[allow(clippy::type_complexity)]
    fn parse_witness_stacks(&self) -> Result<Vec<(usize, Vec<Vec<u8>>)>, WitnessCarrierError>;
}

impl SakeWitnessCarrier for TxOut {
    /// Generates a SAKE witness carrier scriptPubkey from multiple script
    /// witness stacks.
    fn sake_witness_carrier(
        stacks: &[(usize, Vec<Vec<u8>>)],
    ) -> Result<TxOut, WitnessCarrierError> {
        for (_, stack) in stacks {
            if stack.len() > MAX_STACK_SIZE {
                return Err(WitnessCarrierError::TooManyElements);
            }
            for element in stack {
                if element.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(WitnessCarrierError::InvalidElement);
                }
            }
        }

        let mut bytes = vec![];

        // 1. "SAKE" (4 bytes)
        bytes.extend_from_slice(PREFIX);

        // 2. Version (1 byte)
        bytes.push(MAX_SUPPORTED_VERSION);

        // Stacks
        for (input_index, stack) in stacks {
            // 4.1
            crate::varint::encode_vec(&mut bytes, *input_index as u64);

            // 4.2 Stack len
            crate::varint::encode_vec(&mut bytes, stack.len() as u64);

            // 4.3 Stack elements
            for element in stack {
                crate::varint::encode_vec(&mut bytes, element.len() as u64);
                bytes.extend_from_slice(element);
            }
        }

        let mut data = PushBytesBuf::new();
        data.extend_from_slice(&bytes)
            .map_err(|_| WitnessCarrierError::PayloadTooLong)?;

        Ok(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(data),
        })
    }

    /// Parses the witness stacks from an `OP_RETURN` output.
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
        if version_data[0] > MAX_SUPPORTED_VERSION {
            return Err(WitnessCarrierError::UnsupportedVersion);
        }

        // --- Parse Stacks ---

        let mut witness_stacks = Vec::new();

        // Check if there is more data to read (cursor position < payload length)
        while cursor.position() < payload.len() as u64 {
            let input_index = match VarInt::consensus_decode(&mut cursor) {
                Ok(v) => {
                    usize::try_from(v.0).map_err(|_| WitnessCarrierError::InvalidInputIndex)?
                }
                Err(_) => return Err(WitnessCarrierError::InvalidInputIndex),
            };
            let n = match VarInt::consensus_decode(&mut cursor) {
                Ok(v) => {
                    usize::try_from(v.0).map_err(|_| WitnessCarrierError::InvalidElementsCount)?
                }
                Err(_) => return Err(WitnessCarrierError::InvalidElementsCount),
            };
            if n > MAX_STACK_SIZE {
                return Err(WitnessCarrierError::TooManyElements);
            }

            let mut stack = Vec::with_capacity(n);

            for _ in 0..n {
                let element_len = match VarInt::consensus_decode(&mut cursor) {
                    Ok(v) => {
                        usize::try_from(v.0).map_err(|_| WitnessCarrierError::InvalidElement)?
                    }
                    Err(_) => return Err(WitnessCarrierError::InvalidElement),
                };
                let position = usize::try_from(cursor.position())
                    .map_err(|_| WitnessCarrierError::InvalidElement)?;
                let remaining = payload.len().saturating_sub(position);
                if element_len > MAX_SCRIPT_ELEMENT_SIZE || element_len > remaining {
                    return Err(WitnessCarrierError::InvalidElement);
                }

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

/// Error from a SAKE witness carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessCarrierError {
    /// The output script does not start with `OP_RETURN`.
    NotOpReturn,
    /// The payload does not start with the `SAKE` prefix.
    MissingPrefix,
    /// The payload has no version byte.
    MissingVersion,
    /// The version is not supported.
    UnsupportedVersion,
    /// The input index is invalid.
    InvalidInputIndex,
    /// The element count is invalid.
    InvalidElementsCount,
    /// A stack element is invalid or larger than 520 bytes.
    InvalidElement,
    /// A stack holds more than 1000 elements.
    TooManyElements,
    /// The payload is too large for one push.
    PayloadTooLong,
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    // Define the constraints for the generated test case data.
    prop_compose! {
        // Generate a single byte vector (the innermost element)
        fn arb_element()(
            len in 0..=520usize,
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
            let witness_carrier = TxOut::sake_witness_carrier(&stacks).expect("valid SAKE witness carrier");

            let parsed = match witness_carrier.parse_witness_stacks() {
                Ok(p) => p,
                Err(e) => {
                    panic!("Parsing failed unexpectedly: {e:?} for stacks: {stacks:?}");
                }
            };

            assert_eq!(parsed, stacks, "Round-trip failed: original != parsed");
        }
    }

    #[test]
    fn test_carrier_rejects_oversized_element() {
        let stacks = vec![(0usize, vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE + 1]])];
        assert!(matches!(
            TxOut::sake_witness_carrier(&stacks),
            Err(WitnessCarrierError::InvalidElement)
        ));
    }

    #[test]
    fn test_carrier_rejects_too_many_elements() {
        let stacks = vec![(0usize, vec![Vec::new(); MAX_STACK_SIZE + 1])];
        assert!(matches!(
            TxOut::sake_witness_carrier(&stacks),
            Err(WitnessCarrierError::TooManyElements)
        ));
    }

    #[test]
    fn test_carrier_accepts_limits() {
        let stacks = vec![(
            0usize,
            vec![vec![0u8; MAX_SCRIPT_ELEMENT_SIZE]; MAX_STACK_SIZE],
        )];
        assert!(TxOut::sake_witness_carrier(&stacks).is_ok());
    }
}
