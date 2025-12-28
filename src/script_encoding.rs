//! The script encoding the emulated SAKE script

use bitcoin::{
    ScriptBuf, XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_DROP, OP_GREATERTHANOREQUAL},
    script::{PushBytesBuf, PushBytesError},
};

pub(crate) const PREFIX: &[u8; 4] = b"SAKE";
pub(crate) const MAX_SUPPORTED_VERSION_VERSION: u8 = 0;
pub(crate) const VERSION_LEN: usize = 1;

pub trait TryIntoSakeScript {
    /// - oracles: List of the emulation oracles' public keys in deterministic order.
    /// - threshold: Minimum number of oracles required to sign on the emulation success.
    fn try_into_sake_script(
        self,
        oracles: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<ScriptBuf, ScriptEncodingError>;
}

impl TryIntoSakeScript for ScriptBuf {
    fn try_into_sake_script(
        self: ScriptBuf,
        oracles: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<ScriptBuf, ScriptEncodingError> {
        if oracles.is_empty() {
            return Err(ScriptEncodingError::MissingOracles);
        }

        let mut bytes = PushBytesBuf::with_capacity(PREFIX.len() + VERSION_LEN + self.len());

        bytes.extend_from_slice(PREFIX).expect("infallible");
        bytes
            .push(MAX_SUPPORTED_VERSION_VERSION)
            .expect("infallible");
        bytes
            .extend_from_slice(self.as_bytes())
            .map_err(ScriptEncodingError::SizeLimit)?;

        let mut builder = ScriptBuf::builder()
            // Script encoding
            .push_slice(bytes)
            .push_opcode(OP_DROP);

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

pub(crate) fn extract_encoded_scripts(
    inputs: &[(usize, ScriptBuf)],
) -> Result<Vec<(usize, ScriptBuf)>, ScriptDecodingError> {
    let results: Result<Vec<Option<(usize, ScriptBuf)>>, _> = inputs
        .iter()
        .map(|(i, script)| extract_encoded_script(script).map(|o| o.map(|s| (*i, s))))
        .collect();

    // Convert Vec<Option<T>> → Vec<T>, preserving errors
    results.map(|vec| vec.into_iter().flatten().collect())
}

fn extract_encoded_script(script: &ScriptBuf) -> Result<Option<ScriptBuf>, ScriptDecodingError> {
    let mut candidates = Vec::new();

    for instruction in script.instructions().flatten() {
        if let bitcoin::script::Instruction::PushBytes(bytes) = instruction {
            let bytes = bytes.as_bytes();
            if bytes.starts_with(PREFIX) {
                candidates.push(bytes);
            }
        }
    }

    if candidates.len() > 1 {
        return Err(ScriptDecodingError::MultipleEncodedScripts);
    }

    for &bytes in &candidates {
        if let Some(&version) = bytes.get(PREFIX.len()) {
            if version > MAX_SUPPORTED_VERSION_VERSION {
                return Err(ScriptDecodingError::UnsupportedVersion);
            }

            let payload_start = PREFIX.len() + VERSION_LEN;
            if payload_start <= bytes.len() {
                let encoded = bytes[payload_start..].to_vec();
                let script = ScriptBuf::from_bytes(encoded);
                return Ok(Some(script));
            }
        } else {
            return Err(ScriptDecodingError::MultipleEncodedScripts);
        }
    }

    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptEncodingError {
    /// SAKE script seems to be larger than the PushBytes size limit
    SizeLimit(PushBytesError),
    /// No oracles XOnlyPublicKeys were provided,
    /// which risks that anyone can spend this script's input.
    MissingOracles,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptDecodingError {
    /// Input script contains multiple SAKE emulated scripts
    MultipleEncodedScripts,
    /// Missing version number
    MissingVersion,
    /// Version number is larger than the max supported version
    UnsupportedVersion,
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
            { b"world".to_vec() }
            OP_CAT
            { b"hello world".to_vec() }
            OP_EQUALVERIFY

            { 1 }
        };

        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(&secp, &mut rng);
        let pk = keypair.x_only_public_key().0;

        let script = script! {
            // CTLV and CSV are OP_NOPs in the emulator.
            // So they have to happen before the OP_IF
            { 100 }
            OP_CSV
            OP_DROP

            { sake_script.clone().try_into_sake_script(&[pk], 1).unwrap() }
        };

        let decoded = extract_encoded_script(&script).unwrap().unwrap();

        assert_eq!(decoded, sake_script)
    }
}
