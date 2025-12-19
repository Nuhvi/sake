//! OP_CSFS [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)

use bitcoin::{Opcode, XOnlyPublicKey, opcodes::all::OP_NOP9, secp256k1};

pub const OP_CSFS: Opcode = OP_NOP9;

use crate::{
    Exec,
    exec::{ExecError, VALIDATION_WEIGHT_PER_SIGOP_PASSED},
};

impl<'a, 'b> Exec<'a, 'b> {
    /// Internal logic for BIP 348 CSFS
    /// Returns Ok(true) to push 1, Ok(false) to push 0 (empty vec), or Err to fail script.
    pub(crate) fn verify_sig_from_stack(
        &mut self,
        sig_bytes: &[u8],
        msg_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<bool, ExecError> {
        // 1. If the public key size is zero, the script MUST fail.
        if pk_bytes.is_empty() {
            return Err(ExecError::PubkeyType);
        }

        // 2. If the signature is the empty vector, push 0 and continue.
        // This does NOT count against the sigops budget.
        if sig_bytes.is_empty() {
            return Ok(false);
        }

        // 3. Sigops Budget: If sig is not empty, it counts towards the limit.
        self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if self.validation_weight < 0 {
            return Err(ExecError::TapscriptValidationWeight);
        }

        // 4. Public Key Branching
        if pk_bytes.len() == 32 {
            // Known Key Type (BIP 340 Schnorr)
            let pk = XOnlyPublicKey::from_slice(pk_bytes).map_err(|_| ExecError::PubkeyType)?;

            // BIP 340 signature verification
            // Note: BIP 348 allows arbitrary msg lengths;
            // but rust-secp256k1 expects a 32-byte digest.
            if msg_bytes.len() != 32 {
                return Err(ExecError::SchnorrSig);
            }
            let msg = secp256k1::Message::from_digest_slice(msg_bytes)
                .map_err(|_| ExecError::SchnorrSig)?;

            let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)
                .map_err(|_| ExecError::SchnorrSigSize)?;

            // BIP 348: If signature is not empty and validation fails, the script MUST fail.
            self.secp
                .verify_schnorr(&sig, &msg, &pk)
                .map_err(|_| ExecError::SchnorrSig)?;
        } else {
            // 5. Unknown Public Key Type: Size is not 0 and not 32.
            // Signature verification succeeds as if it were a known type.
            // This is for future soft-fork compatibility.
        }

        // Success pushes 1
        Ok(true)
    }

    pub(crate) fn handle_op_csfs(&mut self) -> Result<(), ExecError> {
        // Stack: <sig> <msg> <pubkey> (Top is pubkey)
        let pk = self.stack.topstr(-1)?;
        let msg = self.stack.topstr(-2)?;
        let sig = self.stack.topstr(-3)?;

        // Perform verification according to BIP 348 rules
        let success = self.verify_sig_from_stack(&sig, &msg, &pk)?;

        // Push result: 1 for success, empty vector for "null-fail"
        if success {
            self.stack.pushnum(1);
        } else {
            self.stack.pushstr(&[]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // TODO: support OP_CSFS in bitcoin_script

    use crate::exec::sake_opcodes::tests::validate_single_script;

    use super::*;
    use bitcoin::{
        key::Secp256k1,
        opcodes::all::{OP_2DROP, OP_DROP, OP_EQUALVERIFY},
        script,
    };

    #[test]
    fn test_op_csfs_unknown_key_type_succeeds() {
        let script = script::Builder::new()
            .push_opcode(OP_CSFS)
            .push_int(1)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_2DROP)
            .push_opcode(OP_DROP)
            .push_int(1)
            .into_script();
        let witness = vec![
            vec![0x01; 64], // Non-empty Sig
            vec![0x00; 32], // Msg
            vec![0xAA; 33], // Unknown PK type (33 bytes)
        ];

        validate_single_script(script, witness).unwrap()
    }

    #[test]
    fn test_op_csfs_empty_sig_pushes_zero() {
        let script = script::Builder::new()
            .push_opcode(OP_CSFS)
            .push_int(0)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_2DROP)
            .push_opcode(OP_DROP)
            .push_int(1)
            .into_script();
        let witness = vec![
            vec![],         // EMPTY SIG
            vec![0x00; 32], // Msg
            vec![0x01; 32], // PK
        ];

        validate_single_script(script, witness).unwrap()
    }

    #[test]
    fn test_op_csfs_pk_size_zero_fails() {
        let script = script::Builder::new().push_opcode(OP_CSFS).into_script();
        let witness = vec![
            vec![0x01; 64],
            vec![0x00; 32],
            vec![], // PK SIZE ZERO
        ];

        let res = validate_single_script(script, witness);

        assert!(res.is_err(), "PK size 0 must fail script");
    }

    #[test]
    fn test_op_csfs_invalid_sig_hard_fail() {
        let script = script::Builder::new().push_opcode(OP_CSFS).into_script();
        let witness = vec![
            vec![0xff; 64], // Invalid but non-empty sig
            vec![0x00; 32],
            vec![0x01; 32],
        ];

        let res = validate_single_script(script, witness);
        assert!(
            res.is_err(),
            "Invalid non-empty signature must terminate with error"
        );
    }

    #[test]
    fn test_op_csfs_valid_sig_succeeds() {
        let secp = Secp256k1::new();
        // Generate a random keypair for the test
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(&secp, &mut rng);
        let (x_only_pk, _) = keypair.x_only_public_key();

        // BIP 348 requires a 32-byte message for the current BIP 340 implementation
        let msg_bytes = [0x42u8; 32];
        let msg = secp256k1::Message::from_digest_slice(&msg_bytes).unwrap();
        let sig = secp.sign_schnorr(&msg, &keypair);

        let script = script::Builder::new()
            .push_opcode(OP_CSFS)
            .push_int(1)
            .push_opcode(OP_EQUALVERIFY)
            // Cleaning up the peeked elements since handle_op_csfs doesn't pop yet
            .push_opcode(OP_2DROP)
            .push_opcode(OP_DROP)
            .push_int(1)
            .into_script();

        let witness = vec![
            sig.as_ref().to_vec(),          // <sig>
            msg_bytes.to_vec(),             // <msg>
            x_only_pk.serialize().to_vec(), // <pubkey>
        ];

        validate_single_script(script, witness).expect("Valid Schnorr signature should pass CSFS");
    }
}
