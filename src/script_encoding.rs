//! The script encoding the emulated SAKE script

use std::io::Cursor;

use bitcoin::{
    ScriptBuf, VarInt, XOnlyPublicKey,
    consensus::Decodable,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_DROP, OP_GREATERTHANOREQUAL},
    script::{Instruction, PushBytesBuf, PushBytesError},
};

pub(crate) const PREFIX: &[u8; 4] = b"SAKE";
/// Highest supported encoding version (0 = single push, 1 = chunked).
pub(crate) const MAX_SUPPORTED_VERSION: u8 = 1;
pub(crate) const VERSION_LEN: usize = 1;
const VERSION_SINGLE_PUSH: u8 = 0;
const VERSION_CHUNKED: u8 = 1;
/// Maximum size of one tapscript push element (BIP-342).
const MAX_PUSH_SIZE: usize = 520;
/// Maximum number of oracle keys (BIP-342 initial stack element limit).
///
/// The native tapscript needs one initial stack element for each oracle
/// signature, so more than 1000 oracles can never be spent.
pub const MAX_ORACLES: usize = 1000;

/// Encodes an emulated script into a tapscript that SAKE oracles verify.
pub trait EncodeSakeScript {
    /// - oracles: List of the emulation oracles' public keys in deterministic order.
    ///   The list is limited to [`MAX_ORACLES`] entries.
    /// - threshold: Minimum number of oracles required to sign on the emulation success.
    ///
    /// Scripts that fit in a single 520-byte push use encoding version 0.
    /// Larger scripts use version 1: a header push with the total length,
    /// followed by `ceil(len / 520)` chunk pushes, each followed by OP_DROP.
    fn encode_sake_script(
        self,
        oracles: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<ScriptBuf, ScriptEncodingError>;
}

impl EncodeSakeScript for ScriptBuf {
    fn encode_sake_script(
        self: ScriptBuf,
        oracles: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<ScriptBuf, ScriptEncodingError> {
        if oracles.is_empty() {
            return Err(ScriptEncodingError::MissingOracles);
        }
        if oracles.len() > MAX_ORACLES {
            return Err(ScriptEncodingError::TooManyOracles);
        }
        if threshold == 0 || threshold > oracles.len() || (oracles.len() == 1 && threshold != 1) {
            return Err(ScriptEncodingError::InvalidThreshold);
        }

        let mut builder = ScriptBuf::builder();

        if PREFIX.len() + VERSION_LEN + self.len() <= MAX_PUSH_SIZE {
            // Version 0: the whole script fits in one push.
            let mut payload = Vec::with_capacity(PREFIX.len() + VERSION_LEN + self.len());
            payload.extend_from_slice(PREFIX);
            payload.push(VERSION_SINGLE_PUSH);
            payload.extend_from_slice(self.as_bytes());
            let bytes = PushBytesBuf::try_from(payload).map_err(ScriptEncodingError::SizeLimit)?;
            builder = builder.push_slice(bytes).push_opcode(OP_DROP);
        } else {
            // Version 1: length header followed by <=520-byte chunks.
            let mut header = Vec::with_capacity(PREFIX.len() + VERSION_LEN + 9);
            header.extend_from_slice(PREFIX);
            header.push(VERSION_CHUNKED);
            crate::varint::encode_vec(&mut header, self.len() as u64);
            let header = PushBytesBuf::try_from(header).map_err(ScriptEncodingError::SizeLimit)?;
            builder = builder.push_slice(header).push_opcode(OP_DROP);

            for chunk in self.as_bytes().chunks(MAX_PUSH_SIZE) {
                let chunk = PushBytesBuf::try_from(chunk.to_vec())
                    .map_err(ScriptEncodingError::SizeLimit)?;
                builder = builder.push_slice(chunk).push_opcode(OP_DROP);
            }
        }

        // Oracle signature verification
        for (i, oracle) in oracles.iter().enumerate() {
            builder = builder.push_x_only_key(oracle);
            if i == 0 {
                builder = builder.push_opcode(OP_CHECKSIG);
            } else {
                builder = builder.push_opcode(OP_CHECKSIGADD);
            }
        }

        if oracles.len() > 1 {
            builder = builder
                .push_int(threshold as i64)
                .push_opcode(OP_GREATERTHANOREQUAL);
        }

        Ok(builder.into_script())
    }
}

pub(crate) fn extract_encoded_script(
    script: &ScriptBuf,
) -> Result<Option<ScriptBuf>, ScriptDecodingError> {
    let mut instructions = script.instructions();

    while let Some(instruction) = instructions.next() {
        let instruction = instruction.map_err(ScriptDecodingError::Script)?;
        let Instruction::PushBytes(bytes) = instruction else {
            continue;
        };
        let bytes = bytes.as_bytes();
        if !bytes.starts_with(PREFIX) {
            continue;
        }

        let version = *bytes
            .get(PREFIX.len())
            .ok_or(ScriptDecodingError::MissingVersion)?;
        if version > MAX_SUPPORTED_VERSION {
            return Err(ScriptDecodingError::UnsupportedVersion);
        }
        let payload_start = PREFIX.len() + VERSION_LEN;

        return match version {
            VERSION_SINGLE_PUSH => {
                let encoded = bytes.get(payload_start..).unwrap_or_default().to_vec();
                // Version 0 must be a single encoded script.
                for instruction in instructions {
                    if let Instruction::PushBytes(bytes) =
                        instruction.map_err(ScriptDecodingError::Script)?
                        && bytes.as_bytes().starts_with(PREFIX)
                    {
                        return Err(ScriptDecodingError::MultipleEncodedScripts);
                    }
                }
                Ok(Some(ScriptBuf::from_bytes(encoded)))
            }
            VERSION_CHUNKED => {
                let length_bytes = bytes
                    .get(payload_start..)
                    .ok_or(ScriptDecodingError::MissingLength)?;
                let mut cursor = Cursor::new(length_bytes);
                let total_len = VarInt::consensus_decode(&mut cursor)
                    .map_err(|_| ScriptDecodingError::InvalidLength)
                    .and_then(|length| {
                        usize::try_from(length.0).map_err(|_| ScriptDecodingError::InvalidLength)
                    })?;

                let mut encoded = Vec::new();
                if total_len == 0 {
                    return Ok(Some(ScriptBuf::from_bytes(encoded)));
                }

                for instruction in instructions {
                    match instruction.map_err(ScriptDecodingError::Script)? {
                        Instruction::PushBytes(chunk) => {
                            let new_len = encoded
                                .len()
                                .checked_add(chunk.len())
                                .ok_or(ScriptDecodingError::InvalidLength)?;
                            if new_len > total_len {
                                return Err(ScriptDecodingError::InvalidLength);
                            }
                            encoded.extend_from_slice(chunk.as_bytes());
                            if encoded.len() == total_len {
                                return Ok(Some(ScriptBuf::from_bytes(encoded)));
                            }
                        }
                        Instruction::Op(OP_DROP) => {}
                        _ => return Err(ScriptDecodingError::InvalidChunk),
                    }
                }
                Err(ScriptDecodingError::InvalidLength)
            }
            _ => Err(ScriptDecodingError::UnsupportedVersion),
        };
    }

    Ok(None)
}

/// Error when a script cannot be encoded for SAKE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptEncodingError {
    /// SAKE script seems to be larger than the PushBytes size limit
    SizeLimit(PushBytesError),
    /// No oracles XOnlyPublicKeys were provided,
    /// which risks that anyone can spend this script's input.
    MissingOracles,
    /// The oracle list is longer than [`MAX_ORACLES`] (1000 entries). The
    /// native tapscript would need more initial stack elements than BIP-342
    /// allows, so the input could never be spent.
    TooManyOracles,
    /// The threshold must be between 1 and the number of oracles. A threshold
    /// of 0 with multiple oracles would make the input anyone-can-spend.
    InvalidThreshold,
}

/// Error when a tapscript has an invalid SAKE encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptDecodingError {
    /// Input script contains multiple SAKE emulated scripts
    MultipleEncodedScripts,
    /// Missing version number
    MissingVersion,
    /// Version number is larger than the max supported version
    UnsupportedVersion,
    /// Version 1 header is missing the script length
    MissingLength,
    /// Version 1 script length is inconsistent with the chunks
    InvalidLength,
    /// Version 1 chunk stream contains a non-push, non-OP_DROP instruction
    InvalidChunk,
    /// The native script could not be parsed
    Script(bitcoin::script::Error),
}

#[cfg(test)]
mod tests {

    use bitcoin::{key::Secp256k1, secp256k1};
    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    use super::*;

    #[test]
    fn test_single_oracle() {
        let sake_script = script! {
            // Test OP_CAT
            <"world"> OP_CAT
            <"hello world"> OP_EQUALVERIFY
            1
        };

        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(&secp, &mut rng);
        let pk = keypair.x_only_public_key().0;

        let script = script! {
            // CTLV and CSV are OP_NOPs in the emulator.
            // So they have to happen before the OP_IF
            100 OP_CSV OP_DROP

            // OP_PUSHBYTES_<len> b"SAKE"<MAX_SUPPORTED_VERSION=0><Encoded Script> OP_DROP
            // OP_PUSHBYTES_32 <Oracle 1 Pubkey> OP_CHECKSIG
            <sake_script.clone().encode_sake_script(&[pk], 1).unwrap()>
        };

        let decoded = extract_encoded_script(&script).unwrap().unwrap();

        assert_eq!(decoded, sake_script)
    }

    #[test]
    fn test_invalid_thresholds() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let pk = secp256k1::Keypair::new(&secp, &mut rng)
            .x_only_public_key()
            .0;
        let script = script! { OP_1 };

        assert!(matches!(
            script.clone().encode_sake_script(&[pk], 0),
            Err(ScriptEncodingError::InvalidThreshold)
        ));
        assert!(matches!(
            script.clone().encode_sake_script(&[pk], 2),
            Err(ScriptEncodingError::InvalidThreshold)
        ));
        assert!(matches!(
            script.clone().encode_sake_script(&[pk, pk], 0),
            Err(ScriptEncodingError::InvalidThreshold)
        ));
        assert!(matches!(
            script.clone().encode_sake_script(&[pk, pk], 3),
            Err(ScriptEncodingError::InvalidThreshold)
        ));
        assert!(script.clone().encode_sake_script(&[pk], 1).is_ok());
        assert!(script.encode_sake_script(&[pk, pk], 2).is_ok());
    }

    #[test]
    fn test_too_many_oracles() {
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let pk = secp256k1::Keypair::new(&secp, &mut rng)
            .x_only_public_key()
            .0;
        let oracles = vec![pk; MAX_ORACLES + 1];
        let script = script! { OP_1 };

        assert!(matches!(
            script.encode_sake_script(&oracles, 1),
            Err(ScriptEncodingError::TooManyOracles)
        ));
    }

    #[test]
    fn test_large_script_encoding() {
        // Test encoding a moderately large script (100KB)
        // This should succeed as it's well below the PushBytes limit (~4GB)
        let large_script_bytes = vec![0x51u8; 100_000]; // 100KB of OP_PUSHNUM_1
        let large_script = ScriptBuf::from_bytes(large_script_bytes);

        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(&secp, &mut rng);
        let pk = keypair.x_only_public_key().0;

        let result = large_script.encode_sake_script(&[pk], 1);
        assert!(
            result.is_ok(),
            "Large script (100KB) should encode successfully"
        );

        let encoded_script = result.unwrap();
        let decoded = extract_encoded_script(&encoded_script).unwrap().unwrap();
        assert_eq!(
            decoded.as_bytes().len(),
            100_000,
            "Decoded script should match original size"
        );
    }
}
