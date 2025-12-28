//! The script encoding the emulated SAKE script

use bitcoin::{
    ScriptBuf, XOnlyPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_DROP, OP_GREATERTHANOREQUAL},
    script::{PushBytes, PushBytesError},
};

const PREFIX: &[u8; 4] = b"SAKE";

pub trait TryIntoSakeScript {
    /// - oracles: List of the emulation oracles' public keys in deterministic order.
    /// - threshold: Minimum number of oracles required to sign on the emulation success.
    fn try_into_sake_script(
        self,
        oracles: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<ScriptBuf, EncodingScriptError>;
}

impl TryIntoSakeScript for ScriptBuf {
    fn try_into_sake_script(
        self: ScriptBuf,
        oracles: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<ScriptBuf, EncodingScriptError> {
        if oracles.is_empty() {
            return Err(EncodingScriptError::MissingOracles);
        }

        let bytes: &PushBytes = self
            .as_bytes()
            .try_into()
            .map_err(|err| EncodingScriptError::SizeLimit(err))?;

        let mut builder = ScriptBuf::builder()
            .push_slice(PREFIX)
            .push_slice(bytes)
            .push_opcode(OP_DROP);

        for (i, oracle) in oracles.iter().enumerate() {
            builder = builder.push_x_only_key(oracle);
            if i == 0 {
                builder = builder.push_opcode(OP_CHECKSIG);
            } else {
                builder = builder.push_opcode(OP_CHECKSIGADD);
            }
        }

        builder = builder
            .push_int(threshold as i64)
            .push_opcode(OP_GREATERTHANOREQUAL);

        Ok(builder.into_script())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingScriptError {
    /// SAKE script seems to be larger than the PushBytes size limit
    SizeLimit(PushBytesError),
    /// No oracles XOnlyPublicKeys were provided,
    /// which risks that anyone can spend this script's input.
    MissingOracles,
}
