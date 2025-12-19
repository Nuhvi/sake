use bitcoin::{
    TapSighashType, XOnlyPublicKey,
    secp256k1::{self, Message},
    sighash::Prevouts,
};

use crate::{
    Exec,
    exec::{ExecError, VALIDATION_WEIGHT_PER_SIGOP_PASSED},
};

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn verify_transaction_signature(
        &mut self,
        sig: &[u8],
        pk: &[u8],
    ) -> Result<bool, ExecError> {
        let (sig, sighash_type) = if sig.len() == 65 {
            let b = *sig.last().unwrap();
            let sig = &sig[0..sig.len() - 1];

            if b == TapSighashType::Default as u8 {
                return Err(ExecError::SchnorrSigHashtype);
            }
            //TODO(stevenroose) core does not error here
            let sht =
                TapSighashType::from_consensus_u8(b).map_err(|_| ExecError::SchnorrSigHashtype)?;
            (sig, sht)
        } else {
            (sig, TapSighashType::Default)
        };

        let sighash = self
            .sighashcache
            .taproot_signature_hash(
                self.input_idx,
                &Prevouts::All(self.prevouts),
                None,
                Some((self.leaf_hash, u32::MAX)),
                sighash_type,
            )
            .expect("Prevout consistency checked at Exec init");

        self.verify_signature(sig, pk, sighash.into())
    }

    /// Shared logic for all Schnorr-based signature checks (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD, and CSFS).
    /// Takes a closure to provide the message digest only when needed.
    pub(crate) fn verify_signature(
        &mut self,
        sig_bytes: &[u8],
        pk_bytes: &[u8],
        msg: Message,
    ) -> Result<bool, ExecError> {
        // 1. Sigop Budgeting
        if !sig_bytes.is_empty() {
            self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if self.validation_weight < 0 {
                return Err(ExecError::TapscriptValidationWeight);
            }
        }

        // 2. Public Key Validation
        if pk_bytes.is_empty() {
            return Err(ExecError::PubkeyType);
        }

        // 3. Null-Fail Rule
        if sig_bytes.is_empty() {
            return Ok(false);
        }

        // 4. Known Key Type (32-byte X-Only)
        if pk_bytes.len() == 32 {
            let pk = XOnlyPublicKey::from_slice(pk_bytes).map_err(|_| ExecError::PubkeyType)?;

            // Note: handle_op_checksig handles sighash bytes, so sig_bytes here is raw 64 bytes
            let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|_| ExecError::SchnorrSigSize)?;

            dbg!(&sig, &msg, &pk);
            dbg!("HERE");
            self.secp
                .verify_schnorr(&sig, &msg, &pk)
                .map_err(|_| ExecError::SchnorrSig)?;
        }

        // 5. Unknown Key Type (Success/Upgrade Path)
        // If pk.len() != 32 and is not empty, it succeeds as per BIP 341/348.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{exec::Exec, tests::validate_single_script};

    use bitcoin::{
        Amount, TapLeafHash, TapSighashType, Transaction, TxOut,
        key::{Keypair, Secp256k1},
        opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY},
        script,
        secp256k1::{self},
        sighash::{Prevouts, SighashCache},
        taproot::LeafVersion,
    };

    #[test]
    fn test_op_checksig_unknown_key_type_succeeds() {
        let script = script::Builder::new()
            .push_opcode(OP_CHECKSIG)
            .push_int(1)
            .push_opcode(OP_EQUALVERIFY)
            .push_int(1)
            .into_script();
        let witness = vec![
            vec![0x01; 64], // Non-empty Sig
            vec![0xAA; 33], // Unknown PK type (33 bytes)
        ];

        validate_single_script(script, witness).unwrap()
    }

    #[test]
    fn test_op_checksig_empty_sig_pushes_zero() {
        let script = script::Builder::new()
            .push_opcode(OP_CHECKSIG)
            .push_int(0)
            .push_opcode(OP_EQUALVERIFY)
            .push_int(1)
            .into_script();
        let witness = vec![
            vec![],         // EMPTY SIG
            vec![0x01; 32], // PK
        ];

        validate_single_script(script, witness).unwrap()
    }

    #[test]
    fn test_op_checksig_pk_size_zero_fails() {
        let script = script::Builder::new()
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let witness = vec![
            vec![0x01; 64],
            vec![0x00; 32],
            vec![], // PK SIZE ZERO
        ];

        let res = validate_single_script(script, witness);

        assert!(res.is_err(), "PK size 0 must fail script");
    }

    #[test]
    fn test_op_checksig_invalid_sig_hard_fail() {
        let script = script::Builder::new()
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let witness = vec![
            vec![0xff; 64], // Invalid but non-empty sig
            vec![0x01; 32],
        ];

        let res = validate_single_script(script, witness);
        assert!(
            res.is_err(),
            "Invalid non-empty signature must terminate with error"
        );
    }

    #[test]
    fn test_op_checksig_valid_sig_succeeds() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (x_only_pk, _) = keypair.x_only_public_key();

        // 1. Define the script
        let script = bitcoin_script::script! {
            OP_CHECKSIG
            { 1 }
            OP_EQUALVERIFY
            { 1 }
        }
        .compile();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }];

        // Calculate the TapLeafHash for this script
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);

        // Calculate the sighash (the message the interpreter will verify)
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                None,
                Some((leaf_hash, u32::MAX)),
                TapSighashType::Default,
            )
            .expect("Sighash calculation failed");

        // 3. Sign the sighash
        let msg = sighash.into();
        let sig = secp.sign_schnorr(&msg, &keypair);
        dbg!(&sig, &msg, &keypair.x_only_public_key());

        // 4. Construct Witness: <sig> <pk>
        // Note: sig is 64 bytes (Default sighash), pk is 32 bytes
        let witness = vec![sig.as_ref().to_vec(), x_only_pk.serialize().to_vec()];

        // Validate

        let mut sighashcache = SighashCache::new(&tx);
        let mut exec = Exec::new(&mut sighashcache, &prevouts, 0, &script, witness).unwrap();

        loop {
            match exec.exec_next() {
                Ok(_) => continue,
                Err(exec_result) => {
                    assert!(exec_result.success);
                    break;
                }
            }
        }
    }
}
