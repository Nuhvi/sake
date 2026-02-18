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
pub(crate) struct CCVTxState {
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

        let mode_bytes = self.stack.popstr()?;
        let taptree = self.stack.popstr()?;
        let pk = self.stack.popstr()?;
        let index_bytes = self.stack.popstr()?;
        let data = self.stack.popstr()?;

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
        let internal_key =
            self.compute_ccv_internal_key(&naked_key, &data, taptree_hash.as_ref())?;

        // Verify target script matches expected P2TR
        let expected_script = self.make_p2tr_script(&internal_key)?;
        if target_script != expected_script {
            return Err(ExecError::CCVScriptMismatch);
        }

        // Handle amount semantics
        match mode {
            CCV_MODE_CHECK_OUTPUT => {
                // Default: preserve residual amount
                self.ccv_check_output_default(index as usize, target_amount)?;
            }
            CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT => {
                // Deduct: subtract output amount from residual
                self.ccv_check_output_deduct(index as usize, target_amount)?;
            }
            CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT => {
                // Ignore amount: verify script only, no amount checks
                // This mode intentionally does nothing for amount handling
            }
            CCV_MODE_CHECK_INPUT => {
                // Input mode: no amount checks needed
            }
            _ => {
                // Undefined modes are handled earlier (return success)
            }
        }

        Ok(())
    }

    /// Compute the final taproot output key from naked key, data, and taptree
    fn compute_ccv_internal_key(
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
    /// Implements BIP-443 default amount checking logic
    fn ccv_check_output_default(&mut self, index: usize, amount: u64) -> Result<(), ExecError> {
        // Access transaction-wide state
        let tx_state = self
            .ccv_tx_state
            .ok_or(ExecError::CCVAmountConflict)?
            .borrow_mut();

        // BIP-443: Check if output was already checked with deduct mode
        if tx_state.output_checked_deduct[index] {
            return Err(ExecError::CCVAmountConflict);
        }

        // Get residual amount from per-input state
        let residual = self
            .ccv_input_state
            .as_ref()
            .ok_or(ExecError::CCVAmountConflict)?
            .residual_input_amount;

        // BIP-443: The output amount must be at least the minimum required
        let required = tx_state.output_min_amount[index] + residual;
        if amount < required {
            return Err(ExecError::CCVInsufficientAmount);
        }

        // Mark output as checked with default mode
        drop(tx_state); // Release borrow before modifying
        if let Some(tx_state) = self.ccv_tx_state {
            tx_state.borrow_mut().output_checked_default[index] = true;
        }

        Ok(())
    }

    /// Check output with deduct amount semantic
    /// Implements BIP-443 deduct amount checking logic
    fn ccv_check_output_deduct(&mut self, index: usize, amount: u64) -> Result<(), ExecError> {
        // Access transaction-wide state
        let tx_state = self
            .ccv_tx_state
            .ok_or(ExecError::CCVAmountConflict)?
            .borrow_mut();

        // BIP-443: Check if output was already checked with default mode
        if tx_state.output_checked_default[index] {
            return Err(ExecError::CCVAmountConflict);
        }

        // Check if already checked with deduct (can't deduct twice)
        if tx_state.output_checked_deduct[index] {
            return Err(ExecError::CCVAmountConflict);
        }

        // Get residual amount from per-input state
        let residual = self
            .ccv_input_state
            .as_ref()
            .ok_or(ExecError::CCVAmountConflict)?
            .residual_input_amount;

        // BIP-443: Deduct the output amount from residual
        if residual < amount {
            return Err(ExecError::CCVInsufficientAmount);
        }

        // Update the minimum amount requirement for this output
        drop(tx_state); // Release borrow before modifying
        if let Some(tx_state) = self.ccv_tx_state {
            let mut state = tx_state.borrow_mut();
            state.output_min_amount[index] += amount;
            state.output_checked_deduct[index] = true;
        }

        // Update the residual amount for this input
        if let Some(ref mut input_state) = self.ccv_input_state {
            input_state.residual_input_amount -= amount;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_encoding::EncodeSakeScript;
    use crate::witness_carrier::SakeWitnessCarrier;
    use crate::{Error, validate};
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::secp256k1::XOnlyPublicKey;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
    use bitcoin_script::{define_pushable, script};
    use std::str::FromStr;

    define_pushable!();

    fn dummy_oracle_pk() -> XOnlyPublicKey {
        XOnlyPublicKey::from_str("18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166")
            .unwrap()
    }

    // Helper to create a P2TR output with specified internal key and optional taptree
    fn create_p2tr_output(
        internal_key: XOnlyPublicKey,
        merkle_root: Option<bitcoin::taproot::TapNodeHash>,
        amount: u64,
    ) -> TxOut {
        let output_key = if let Some(merkle_root) = merkle_root {
            // Apply BIP-341 taptweak with merkle root
            let mut engine = bitcoin::hashes::sha256::HashEngine::default();
            let tag = b"TapTweak";
            let tag_hash = sha256::Hash::hash(tag);
            engine.input(&tag_hash[..]);
            engine.input(&tag_hash[..]);
            engine.input(&internal_key.serialize());
            engine.input(&merkle_root[..]);
            let tweak_hash = bitcoin::hashes::sha256::Hash::from_engine(engine);

            // Apply tweak
            let pk_bytes = internal_key.serialize();
            let mut compressed_pk = [0u8; 33];
            compressed_pk[0] = 0x02;
            compressed_pk[1..].copy_from_slice(&pk_bytes);
            let full_pk = bitcoin::secp256k1::PublicKey::from_slice(&compressed_pk).unwrap();

            let tweak_scalar =
                bitcoin::secp256k1::SecretKey::from_slice(&tweak_hash.to_byte_array()).unwrap();
            let secp = Secp256k1::signing_only();
            let tweak_point = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &tweak_scalar);

            let tweaked = full_pk.combine(&tweak_point).unwrap();
            let tweaked_bytes = tweaked.serialize();
            XOnlyPublicKey::from_slice(&tweaked_bytes[1..]).unwrap()
        } else {
            // No taptweak - use internal key directly
            internal_key
        };

        // Create P2TR scriptPubKey: OP_1 (0x51) + push 32 bytes + key
        let mut script_bytes = vec![0x51, 0x20]; // OP_1 + push 32 bytes
        script_bytes.extend_from_slice(&output_key.serialize());

        TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        }
    }

    // Helper to compute the expected taproot output key from parameters
    fn compute_expected_internal_key(naked_key: &XOnlyPublicKey, data: &[u8]) -> XOnlyPublicKey {
        // Start with naked key
        let mut current_key = *naked_key;

        // Apply data tweak if data is non-empty
        if !data.is_empty() {
            let mut preimage = Vec::with_capacity(32 + data.len());
            preimage.extend_from_slice(&naked_key.serialize());
            preimage.extend_from_slice(data);
            let data_tweak = sha256::Hash::hash(&preimage);

            // Apply data tweak using point addition
            let pk_bytes = naked_key.serialize();
            let mut compressed_pk = [0u8; 33];
            compressed_pk[0] = 0x02;
            compressed_pk[1..].copy_from_slice(&pk_bytes);
            let full_pk = bitcoin::secp256k1::PublicKey::from_slice(&compressed_pk).unwrap();

            let tweak_scalar =
                bitcoin::secp256k1::SecretKey::from_slice(&data_tweak.to_byte_array()).unwrap();
            let secp = Secp256k1::signing_only();
            let tweak_point = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &tweak_scalar);

            let tweaked = full_pk.combine(&tweak_point).unwrap();
            let tweaked_bytes = tweaked.serialize();
            current_key = XOnlyPublicKey::from_slice(&tweaked_bytes[1..]).unwrap();
        }

        current_key
    }

    #[test]
    fn test_ccv_mode_check_output_success() {
        // BIP-0443: CCV_MODE_CHECK_OUTPUT (mode=0)
        // Verifies output script and checks that output amount >= residual input amount
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        // Compute expected output key (no data, no taptree)
        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        // Create a transaction with matching output
        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        // Create output with the expected key and sufficient amount
        let outputs = [
            create_p2tr_output(internal_key, None, input_amount), // Output 0 matches the expected key
        ];
        dbg!(&internal_key, &outputs[0].script_pubkey.as_bytes());

        // Build the CCV script: verify output 0 has the expected key and amount
        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0> (output 0)
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        // Encode the script and witness
        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "CCV_MODE_CHECK_OUTPUT should succeed with matching output: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_mode_check_output_insufficient_amount() {
        // BIP-0443: CCV_MODE_CHECK_OUTPUT with insufficient output amount should fail
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        // Output has less than input amount
        let outputs = [
            create_p2tr_output(internal_key, None, 500), // Only 500 sats, but input is 1000
        ];

        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0>
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::CCVInsufficientAmount))),
            "Should fail with insufficient amount: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_mode_check_output_ignore_amount() {
        // BIP-0443: CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT (mode=1)
        // Verifies output script but ignores amount entirely
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        // Output has any amount (even 0 should work)
        let outputs = [
            create_p2tr_output(internal_key, None, 0), // 0 sats, but mode 1 ignores amount
        ];

        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_1                              // <mode=1> (CHECK_OUTPUT_IGNORE_AMOUNT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "CCV_MODE_CHECK_OUTPUT_IGNORE_AMOUNT should succeed regardless of amount: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_mode_deduct_amount_success() {
        // BIP-0443: CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT (mode=2)
        // Deducts output amount from residual and allows splitting
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        // First output: 400 sats (will be deducted)
        // Second output: remaining 600 sats (verified with default mode)
        let internal_key_2 = compute_expected_internal_key(&naked_key, &[]);
        let outputs = [
            create_p2tr_output(internal_key, None, 400),
            create_p2tr_output(internal_key_2, None, 600),
        ];

        // Script that first deducts from output 0, then sends rest to output 1
        let ccv_script = script! {
            // First: Deduct 400 from output 0
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY

            // Then: Send remaining to output 1
            OP_0                              // <data=empty>
            OP_1                              // <index=1>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY

            // Script succeeds if both CCV calls pass
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), outputs[1].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "Deduct + Default mode should work for splitting: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_mode_deduct_insufficient_amount() {
        // BIP-0443: CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT with insufficient input
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 500u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        // Output wants 1000 but input only has 500
        let outputs = [create_p2tr_output(internal_key, None, 1000)];

        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::CCVInsufficientAmount))),
            "Should fail when deducting more than available: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_mode_check_input_success() {
        // BIP-0443: CCV_MODE_CHECK_INPUT (mode=-1)
        // Verifies another input's scriptPubKey (no amount check)
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        // Two inputs - checking input 1 from input 0
        let prevouts = [
            create_p2tr_output(internal_key, None, 1000),
            create_p2tr_output(internal_key, None, 2000),
        ];

        // One output to receive funds
        let outputs = [create_p2tr_output(internal_key, None, 3000)];

        // Script that checks input 1 has the expected key
        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_1                              // <index=1> (check input 1)
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            <vec![0x81u8]>                   // <mode=-1> (CHECK_INPUT) - 0x81 is minimal encoding of -1
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default(), Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "CCV_MODE_CHECK_INPUT should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_mode_check_input_index_minus_one() {
        // BIP-0443: CCV_MODE_CHECK_INPUT with index=-1 (checks current input)
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let prevouts = [create_p2tr_output(internal_key, None, 1000)];

        let outputs = [create_p2tr_output(internal_key, None, 1000)];

        // Script checks itself (current input) using index=-1
        let ccv_script = script! {
            OP_0                              // <data=empty>
            <vec![0x81u8]>                   // <index=-1> (current input)
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            <vec![0x81u8]>                   // <mode=-1> (CHECK_INPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "CCV_MODE_CHECK_INPUT with index=-1 should succeed: {:?}",
            result
        );
    }

    // ========== BIP-0443 Parameter Tests ==========

    #[test]
    fn test_ccv_pk_nums_key() {
        // BIP-0443: pk=empty buffer uses BIP-341 NUMS key
        let nums_key = XOnlyPublicKey::from_slice(&BIP341_NUMS_KEY).unwrap();

        let internal_key = compute_expected_internal_key(&nums_key, &[]);

        let prevouts = [create_p2tr_output(internal_key, None, 1000)];

        let outputs = [create_p2tr_output(internal_key, None, 1000)];

        // Script uses empty pk (NUMS key)
        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            OP_0                              // <pk=empty> (NUMS key)
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0>
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(result.is_ok(), "Empty pk should use NUMS key: {:?}", result);
    }

    #[test]
    fn test_ccv_data_tweak() {
        // BIP-0443: Non-empty data applies data tweak
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let data = b"test data commitment";
        let internal_key = compute_expected_internal_key(&naked_key, data);

        let prevouts = [create_p2tr_output(internal_key, None, 1000)];

        let outputs = [create_p2tr_output(internal_key, None, 1000)];

        // Script with data commitment
        let ccv_script = script! {
            <data.to_vec()>                   // <data>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0>
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "Data tweak should be applied correctly: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_script_mismatch() {
        // BIP-0443: Mismatched script should fail with CCVScriptMismatch
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        // Create output with wrong key (not matching the computed one)
        let wrong_key = XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();

        let prevouts = [create_p2tr_output(naked_key, None, 1000)];

        let outputs = [create_p2tr_output(wrong_key, None, 1000)];

        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0>
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::CCVScriptMismatch))),
            "Should fail with script mismatch: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_undefined_mode_succeeds() {
        // BIP-0443: Undefined modes succeed immediately (soft fork safety)
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let prevouts = [create_p2tr_output(naked_key, None, 1000)];

        // Output doesn't matter since undefined mode should succeed
        let outputs = [TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(), // Invalid script
        }];

        // Mode=3 is undefined
        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_3                              // <mode=3> (undefined)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "Undefined mode should succeed for soft fork safety: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_output_index_out_of_bounds() {
        // BIP-0443: Output index out of bounds should fail
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let prevouts = [create_p2tr_output(naked_key, None, 1000)];

        // Only one output (index 0)
        let outputs = [create_p2tr_output(naked_key, None, 1000)];

        // Try to check output index 5 (doesn't exist)
        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_5                              // <index=5> (out of bounds)
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0>
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::InvalidCCVIndex))),
            "Should fail with invalid index: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_input_index_out_of_bounds() {
        // BIP-0443: Input index out of bounds should fail
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        // Only one input
        let prevouts = [create_p2tr_output(naked_key, None, 1000)];

        let outputs = [create_p2tr_output(naked_key, None, 1000)];

        // Try to check input index 3 (doesn't exist)
        let ccv_script = script! {
            OP_0                              // <data=empty>
            OP_3                              // <index=3> (out of bounds)
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            <vec![0x81u8]>                   // <mode=-1> (CHECK_INPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::InvalidCCVIndex))),
            "Should fail with invalid index: {:?}",
            result
        );
    }

    // ========== BIP-0443 Amount Conflict Tests ==========

    #[test]
    fn test_ccv_conflict_deduct_then_default() {
        // BIP-0443: Cannot use DEFAULT after DEDUCT on same output
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        let outputs = [
            create_p2tr_output(internal_key, None, 600),
            create_p2tr_output(internal_key, None, 400),
        ];

        // First DEDUCT on output 0, then try DEFAULT on same output 0
        let ccv_script = script! {
            // Deduct from output 0
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY
            OP_1

            // Try to use DEFAULT on same output 0 (should conflict)
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), outputs[1].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::CCVAmountConflict))),
            "Should fail with amount conflict for DEDUCT then DEFAULT: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_conflict_default_then_deduct() {
        // BIP-0443: Cannot use DEDUCT after DEFAULT on same output
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        let outputs = [create_p2tr_output(internal_key, None, 1000)];

        // First DEFAULT on output 0, then try DEDUCT on same output 0
        let ccv_script = script! {
            // DEFAULT on output 0
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1

            // Try to DEDUCT on same output 0 (should conflict)
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::CCVAmountConflict))),
            "Should fail with amount conflict for DEFAULT then DEDUCT: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_conflict_double_deduct() {
        // BIP-0443: Cannot use DEDUCT twice on same output
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        let input_amount = 1000u64;
        let prevouts = [TxOut {
            value: Amount::from_sat(input_amount),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        }];

        let outputs = [
            create_p2tr_output(internal_key, None, 400),
            create_p2tr_output(internal_key, None, 400),
        ];

        // Two DEDUCT calls on same output 0
        let ccv_script = script! {
            // First DEDUCT on output 0
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY
            OP_1

            // Second DEDUCT on same output 0 (should conflict)
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_2                              // <mode=2> (CHECK_OUTPUT_DEDUCT_AMOUNT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), outputs[1].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(result, Err(Error::Exec(ExecError::CCVAmountConflict))),
            "Should fail with amount conflict for double DEDUCT: {:?}",
            result
        );
    }

    // ========== BIP-0443 Multiple Input Aggregation Tests ==========

    #[test]
    fn test_ccv_multiple_inputs_aggregate_default() {
        // BIP-0443 Figure 2: Multiple inputs can aggregate to same output using DEFAULT
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let naked_key = keypair.x_only_public_key().0;

        let internal_key = compute_expected_internal_key(&naked_key, &[]);

        // Two inputs with 500 satoshis each
        let prevouts = [
            TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
            },
            TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
            },
        ];

        // One output receiving aggregated amount (1000 sats)
        let outputs = [create_p2tr_output(internal_key, None, 1000)];

        // Script for input 0: DEFAULT on output 0
        let ccv_script_0 = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        // Script for input 1: DEFAULT on output 0 (aggregation)
        let ccv_script_1 = script! {
            OP_0                              // <data=empty>
            OP_0                              // <index=0>
            <naked_key.serialize().to_vec()>  // <pk>
            OP_0                              // <taptree=empty>
            OP_0                              // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY
            OP_1
        };

        let oracle_pk = dummy_oracle_pk();
        let encoded_script_0 = ccv_script_0.encode_sake_script(&[oracle_pk], 0).unwrap();
        let encoded_script_1 = ccv_script_1.encode_sake_script(&[oracle_pk], 1).unwrap();

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![]), (1, vec![])]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default(), Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(
            &tx,
            &prevouts,
            &[(0, encoded_script_0), (1, encoded_script_1)],
        );
        assert!(
            result.is_ok(),
            "Multiple inputs should aggregate with DEFAULT mode: {:?}",
            result
        );
    }

    #[test]
    fn test_ccv_stack_underflow() {
        // Test that insufficient stack elements cause an error
        use crate::tests::validate_single_script;
        use bitcoin_script::{define_pushable, script};

        define_pushable!();

        let script = script! {
            <vec![0x01u8; 32]>  // <data>
            OP_0                // <index=0>
            <vec![0x02u8; 32]>  // <pk>
            // Missing <taptree> and <mode>
            OP_CHECKCONTRACTVERIFY
        };

        let witness: Vec<Vec<u8>> = vec![];
        let result = validate_single_script(script, witness);
        assert!(matches!(
            result,
            Err(crate::Error::Exec(ExecError::InvalidStackOperation))
        ));
    }

    // ========== BIP-0443 Common use cases ==========

    #[test]
    fn test_ccv_state_transition_persist_program_change_data() {
        // BIP-0443: Test state transition where naked key and taptree persist,
        // but data changes via witness with OP_CAT computation
        //
        // This demonstrates a stateful contract where:
        // 1. Old data is passed in witness and validated against input
        // 2. New data is computed as old_data || append_data using OP_CAT
        // 3. Output is created with the computed new_data
        let naked_key = XOnlyPublicKey::from_slice(&BIP341_NUMS_KEY).unwrap();

        // A dummy (taptree) for the contract (actual taptree validation happens on chain)
        let taptree = TapNodeHash::from_slice(&[0; 32]).unwrap();

        // Initial data commitment - this is the expected data in the input
        let old_data = b"old_state_nonce_1234";
        let input_internal_key = compute_expected_internal_key(&naked_key, old_data);

        // Data to append (passed in witness)
        let append_data = b"_5678";

        // Compute expected new data: old_data || append_data
        let mut new_data = old_data.to_vec();
        new_data.extend_from_slice(append_data);

        let output_internal_key = compute_expected_internal_key(&naked_key, &new_data);

        // Input UTXO with old data
        let input_amount = 1000u64;
        let prevouts = [create_p2tr_output(
            input_internal_key,
            Some(taptree),
            input_amount,
        )];

        // Output UTXO with computed new data
        let outputs = [create_p2tr_output(
            output_internal_key,
            Some(taptree),
            input_amount,
        )];

        // Script that:
        // 1. Takes old_data and append_data from witness
        // 2. Verifies input has expected old_data
        // 3. Computes new_data = old_data || append_data using OP_CAT
        // 4. Creates output with computed new_data
        //
        // Witness provides: append_data, old_data (in that order so old_data is on top)
        // Initial stack: <append_data> (bottom) <old_data> (top)
        let ccv_script = script! {
            // Step 1: Verify input has expected old_data (from witness, on top of stack)
            // Duplicate old_data so we can use it for CCV and still have it for CAT
            OP_DUP                            // Stack: <append_data> <old_data> <old_data>

            // Push CCV params for input verification (will be consumed by first CCV)
            <-1>                                // <index=-1>
            <naked_key.serialize().to_vec()>    // <pk=naked_key>
            <taptree.to_byte_array().to_vec()>  // <taptree>
            <-1>                                // <mode=-1> (CHECK_INPUT)
            OP_CHECKCONTRACTVERIFY

            // After first CCV: Stack is <append_data> <old_data>
            // Step 2: Compute new_data = old_data || append_data
            OP_SWAP                           // Stack: <old_data> <append_data>
            OP_CAT                            // Stack: <old_data || append_data>

            // Step 3: Create output with computed new_data
            OP_0                                // <index=0>
            <naked_key.serialize().to_vec()>    // <pk=same_naked_key>
            <taptree.to_byte_array().to_vec()>  // <taptree=same taptree>
            OP_0                                // <mode=0> (CHECK_OUTPUT)
            OP_CHECKCONTRACTVERIFY

            // Script succeeds if both checks pass
            OP_1
        };

        let encoded_script = ccv_script
            .encode_sake_script(&[dummy_oracle_pk()], 0)
            .unwrap();

        // ==== SUCCESS CASE ====
        // Pass correct old_data and append_data in witness
        // Order: last element becomes top of stack
        // We want append_data on top (popped first), old_data below
        let witness_data = vec![append_data.to_vec(), old_data.to_vec()];

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, witness_data)]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), witness_carrier],
        };

        let result = validate(&tx, &prevouts, &[(0, encoded_script.clone())]);
        assert!(
            result.is_ok(),
            "State transition should succeed: witness old_data validated, new_data computed via OP_CAT: {:?}",
            result
        );

        // ==== FAILURE CASE ====
        // Try to use WRONG old_data in witness - should fail with CCVScriptMismatch
        // This simulates an attacker trying to spend from a contract with invalid state
        let wrong_old_data = b"fake_state_nonce_9999";
        let malicious_witness_data = vec![append_data.to_vec(), wrong_old_data.to_vec()];

        let malicious_witness_carrier = TxOut::sake_witness_carrier(&[(0, malicious_witness_data)]);
        let malicious_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![outputs[0].clone(), malicious_witness_carrier],
        };

        let malicious_result = validate(&malicious_tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            matches!(
                malicious_result,
                Err(Error::Exec(ExecError::CCVScriptMismatch))
            ),
            "Should fail when witness provides wrong old_data: {:?}",
            malicious_result
        );
    }
}
