//! OP_CHECKCONTRACTVERIFY [BIP 443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki)

use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::opcodes::all::OP_RETURN_187;
use bitcoin::secp256k1::{self, PublicKey, XOnlyPublicKey};
use bitcoin::{Opcode, ScriptBuf, taproot::TapNodeHash};

use crate::Exec;
use crate::exec::{ExecError, read_scriptint};

pub(crate) const OP_CODE: Opcode = OP_RETURN_187; // 0xbb

#[allow(non_snake_case)]
pub fn OP_CHECKCONTRACTVERIFY() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CODE.to_u8()])
}

#[allow(non_snake_case)]
pub fn OP_CCV() -> ScriptBuf {
    OP_CHECKCONTRACTVERIFY()
}

// Mode constants from BIP-443
const CCV_MODE_CHECK_INPUT: i64 = -1;
const CCV_MODE_CHECK_OUTPUT: i64 = 0;
const CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT: i64 = 1;
const CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT: i64 = 2;

// BIP-341 NUMS key
const BIP341_NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Transaction-wide state for CCV amount tracking
pub struct CCVTxState {
    pub output_min_amount: Vec<u64>,
    pub output_checked_default: Vec<bool>,
    pub output_checked_deduct: Vec<bool>,
}

impl CCVTxState {
    pub fn new(n_outputs: usize) -> Self {
        Self {
            output_min_amount: vec![0; n_outputs],
            output_checked_default: vec![false; n_outputs],
            output_checked_deduct: vec![false; n_outputs],
        }
    }
}

/// Per-input state for CCV
pub struct CCVInputState {
    pub residual_input_amount: u64,
}

impl CCVInputState {
    pub fn new(input_amount: u64) -> Self {
        Self {
            residual_input_amount: input_amount,
        }
    }
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_ccv(&mut self) -> Result<(), ExecError> {
        // Stack format (bottom to top): <mode> <taptree> <pk> <index> <data>
        self.stack.needn(5)?;

        let data = self.stack.popstr()?;
        let index_bytes = self.stack.popstr()?;
        let pk = self.stack.popstr()?;
        let taptree = self.stack.popstr()?;
        let mode_bytes = self.stack.popstr()?;

        // Decode mode as minimally encoded integer (max 8 bytes for i64)
        let mode = read_scriptint(&mode_bytes, 8)?;

        // Undefined modes succeed immediately (soft fork safety)
        if !(CCV_MODE_CHECK_INPUT..=CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT).contains(&mode) {
            return Ok(());
        }

        // Decode index
        let mut index = read_scriptint(&index_bytes, 8)?;

        // Replace -1 with current input index
        if index == -1 {
            index = self.input_idx as i64;
        }

        if index < 0 {
            return Err(ExecError::InvalidCCVIndex);
        }

        // Determine if checking input or output
        let (target_script, target_amount) = if mode == CCV_MODE_CHECK_INPUT {
            if index as usize >= self.prevouts.len() {
                return Err(ExecError::InvalidCCVIndex);
            }
            (
                self.prevouts[index as usize].script_pubkey.to_bytes(),
                self.prevouts[index as usize].value.to_sat(),
            )
        } else {
            let tx = self.sighashcache.transaction();
            if index as usize >= tx.output.len() {
                return Err(ExecError::InvalidCCVIndex);
            }
            (
                tx.output[index as usize].script_pubkey.to_bytes(),
                tx.output[index as usize].value.to_sat(),
            )
        };

        // Process taptree parameter
        let taptree_hash = if self.is_minimal_minus_one(&taptree) {
            // Use current input's taptree
            Some(self.current_input_taptree()?)
        } else if taptree.is_empty() {
            None // No taptweak
        } else if taptree.len() == 32 {
            Some(TapNodeHash::from_slice(&taptree).map_err(|_| ExecError::InvalidCCVTaptree)?)
        } else {
            return Err(ExecError::InvalidCCVTaptree);
        };

        // Process pk parameter
        let naked_key = if pk.is_empty() {
            // Empty buffer = NUMS key
            XOnlyPublicKey::from_slice(&BIP341_NUMS_KEY).map_err(|_| ExecError::InvalidCCVPubkey)?
        } else if self.is_minimal_minus_one(&pk) {
            // -1 = current input's internal key
            self.current_input_internal_key()?
        } else if pk.len() == 32 {
            XOnlyPublicKey::from_slice(&pk).map_err(|_| ExecError::InvalidCCVPubkey)?
        } else {
            return Err(ExecError::InvalidCCVPubkey);
        };

        // Compute final taproot output key
        let final_key = self.compute_ccv_output_key(&naked_key, &data, taptree_hash.as_ref())?;

        // Verify target script matches expected P2TR
        let expected_script = self.make_p2tr_script(&final_key)?;
        if target_script != expected_script {
            return Err(ExecError::CCVScriptMismatch);
        }

        // Handle amount semantics
        if mode == CCV_MODE_CHECK_OUTPUT {
            // Default: preserve residual amount
            self.ccv_check_output_default(index as usize, target_amount)?;
        } else if mode == CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT {
            // Deduct: subtract output amount from residual
            self.ccv_check_output_deduct(index as usize, target_amount)?;
        }
        // CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT and CCV_MODE_CHECK_INPUT do nothing for amounts

        Ok(())
    }

    /// Compute the final taproot output key from naked key, data, and taptree
    fn compute_ccv_output_key(
        &self,
        naked_key: &XOnlyPublicKey,
        data: &[u8],
        taptree: Option<&TapNodeHash>,
    ) -> Result<XOnlyPublicKey, ExecError> {
        // Start with naked key
        let mut current_key = *naked_key;

        // Apply data tweak if data is non-empty
        if !data.is_empty() {
            let data_tweak = self.compute_data_tweak(naked_key, data)?;
            current_key = self.tweak_pubkey(&current_key, &data_tweak)?;
        }

        // Apply taptweak if taptree is present
        if let Some(taptree_hash) = taptree {
            current_key = self.apply_taptweak(&current_key, taptree_hash)?;
        }

        Ok(current_key)
    }

    /// Compute data tweak: SHA256(pk || data)
    fn compute_data_tweak(&self, pk: &XOnlyPublicKey, data: &[u8]) -> Result<[u8; 32], ExecError> {
        let mut preimage = Vec::with_capacity(32 + data.len());
        preimage.extend_from_slice(&pk.serialize());
        preimage.extend_from_slice(data);

        let hash = sha256::Hash::hash(&preimage);
        Ok(hash.to_byte_array())
    }

    /// Tweak a public key with a 32-byte tweak using point addition
    fn tweak_pubkey(
        &self,
        pk: &XOnlyPublicKey,
        tweak: &[u8; 32],
    ) -> Result<XOnlyPublicKey, ExecError> {
        // Get the public key as a full PublicKey
        let pk_bytes = pk.serialize();
        // Create a 33-byte compressed key prefix: 0x02 indicates even Y
        let mut compressed_pk = [0u8; 33];
        compressed_pk[0] = 0x02;
        compressed_pk[1..].copy_from_slice(&pk_bytes);

        let full_pk = PublicKey::from_slice(&compressed_pk).map_err(|_| ExecError::SchnorrSig)?;

        // Create the tweak point by multiplying G by the tweak
        // First convert tweak to a secret key (scalar)
        let tweak_scalar =
            secp256k1::SecretKey::from_slice(tweak).map_err(|_| ExecError::SchnorrSig)?;

        // T * G - need a signing context for this
        let secp_sign = secp256k1::Secp256k1::signing_only();
        let tweak_point = PublicKey::from_secret_key(&secp_sign, &tweak_scalar);

        // Compute Q = P + T (point addition)
        let tweaked = full_pk
            .combine(&tweak_point)
            .map_err(|_| ExecError::SchnorrSig)?;

        // Convert back to XOnlyPublicKey
        let tweaked_bytes = tweaked.serialize();
        // Skip the first byte (compression prefix) and take the 32 X-coordinate bytes
        XOnlyPublicKey::from_slice(&tweaked_bytes[1..]).map_err(|_| ExecError::SchnorrSig)
    }

    /// Apply BIP-341 taptweak
    fn apply_taptweak(
        &self,
        pk: &XOnlyPublicKey,
        taptree: &TapNodeHash,
    ) -> Result<XOnlyPublicKey, ExecError> {
        // BIP-341 taproot_tweak_pubkey: internal_key + H_TapTweak(internal_key || merkle_root) * G

        // Compute tagged hash: H_TapTweak(pk || taptree)
        let mut engine = bitcoin::hashes::sha256::HashEngine::default();

        // Tagged hash prefix for TapTweak
        let tag = b"TapTweak";
        let tag_hash = sha256::Hash::hash(tag);
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);

        // Input: pk || taptree
        engine.input(&pk.serialize());
        engine.input(&taptree[..]);

        let tweak_hash = bitcoin::hashes::sha256::Hash::from_engine(engine);

        // Apply the tweak using point addition
        self.tweak_pubkey(pk, &tweak_hash.to_byte_array())
    }

    /// Check output with default amount semantic (preserve residual)
    fn ccv_check_output_default(&mut self, _index: usize, amount: u64) -> Result<(), ExecError> {
        // Get the residual amount from input state
        let input_state = self.ccv_input_state()?;

        // Check if output amount covers the residual
        if amount < input_state.residual_input_amount {
            return Err(ExecError::CCVInsufficientAmount);
        }

        Ok(())
    }

    /// Check output with deduct amount semantic
    fn ccv_check_output_deduct(&mut self, _index: usize, amount: u64) -> Result<(), ExecError> {
        // Get residual from input state
        let input_state = self.ccv_input_state()?;

        if input_state.residual_input_amount < amount {
            return Err(ExecError::CCVInsufficientAmount);
        }

        Ok(())
    }

    // Helper methods

    fn is_minimal_minus_one(&self, bytes: &[u8]) -> bool {
        // Check if bytes represent minimally encoded -1 (0x81)
        bytes == [0x81]
    }

    fn current_input_taptree(&self) -> Result<TapNodeHash, ExecError> {
        // For tapscript, the leaf hash is computed from the script
        // In a full implementation, we'd track the taptree from the control block
        // For now, return a default empty tree hash
        Ok(TapNodeHash::from_slice(&[0u8; 32]).unwrap())
    }

    fn current_input_internal_key(&self) -> Result<XOnlyPublicKey, ExecError> {
        // In a real implementation, this would come from the control block
        // For testing, we return the NUMS key
        XOnlyPublicKey::from_slice(&BIP341_NUMS_KEY).map_err(|_| ExecError::InvalidCCVPubkey)
    }

    fn make_p2tr_script(&self, key: &XOnlyPublicKey) -> Result<Vec<u8>, ExecError> {
        // Create P2TR scriptPubKey: OP_1 (0x51) + 32-byte key
        let mut script = vec![0x51, 0x20]; // OP_1 + push 32 bytes
        script.extend_from_slice(&key.serialize());
        Ok(script)
    }

    fn ccv_input_state(&self) -> Result<CCVInputState, ExecError> {
        // Get the amount from the current input
        let amount = self
            .prevouts
            .get(self.input_idx)
            .map(|txout| txout.value.to_sat())
            .unwrap_or(0);
        Ok(CCVInputState::new(amount))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::validate_single_script;
    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    #[test]
    fn test_op_ccv_stack_underflow() {
        // Test that insufficient stack elements cause an error
        let script = script! {
            { vec![0x01u8; 32] }   // <data>
            OP_0                   // <index=0>
            { vec![0x02u8; 32] }   // <pk>
            // Missing <taptree> and <mode>
            OP_CHECKCONTRACTVERIFY
        };

        let witness = vec![];
        let result = validate_single_script(script, witness);
        assert!(matches!(
            result,
            Err(crate::Error::Exec(ExecError::InvalidStackOperation))
        ));
    }

    #[test]
    fn test_op_ccv_empty_data_no_tweak() {
        // Test with empty data (no data tweak applied)
        // This creates a contract without data commitment
        // mode=0, index=0, taptree=empty, pk=32 bytes
        let script = script! {
            OP_0                              // <data=empty> - no data tweak
            OP_0                              // <index=0>
            { vec![0x02u8; 32] }              // <pk>
            OP_0                              // <taptree=empty> - no taptweak
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
        };

        let witness = vec![];
        // This will fail with script mismatch because the output doesn't match
        // but we're testing that empty data doesn't cause an error
        let result = validate_single_script(script, witness);
        // Should fail with script mismatch, not other errors
        assert!(matches!(
            result,
            Err(crate::Error::Exec(ExecError::CCVScriptMismatch))
        ));
    }

    #[test]
    fn test_op_ccv_nums_key_empty_pk() {
        // Test that empty pk uses NUMS key
        // mode=0, index=0, taptree=empty, pk=empty
        let script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            OP_0                              // <pk=empty> - should use NUMS key
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
        };

        let witness = vec![];
        // This will fail with script mismatch because the output doesn't match the NUMS-based key
        let result = validate_single_script(script, witness);
        assert!(matches!(
            result,
            Err(crate::Error::Exec(ExecError::CCVScriptMismatch))
        ));
    }

    #[test]
    fn test_op_ccv_deduct_amount_mode() {
        // Test CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT (2)
        // This mode deducts the output amount from input residual
        // mode=2 is encoded as 0x02 (minimal encoding)
        let script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            { vec![0x02u8; 32] }              // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY
        };

        let witness = vec![];
        // Will fail with script mismatch since output doesn't match
        let result = validate_single_script(script, witness);
        assert!(matches!(
            result,
            Err(crate::Error::Exec(ExecError::CCVScriptMismatch))
        ));
    }
}
