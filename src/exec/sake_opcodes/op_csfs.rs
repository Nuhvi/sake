//! OP_CHECKSIGFROMSTACK [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)

use bitcoin::{Opcode, opcodes::all::OP_NOP9, secp256k1::Message};

pub const OP_CHECKSIGFROMSTACK: Opcode = OP_NOP9;

use crate::{Exec, exec::ExecError};

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn handle_op_csfs(&mut self) -> Result<(), ExecError> {
        // Stack: <sig> <msg> <pubkey> (Top is pubkey)
        let pk = self.stack.topstr(-1)?;
        let msg_bytes = self.stack.topstr(-2)?;
        let sig = self.stack.topstr(-3)?;

        if msg_bytes.len() != 32 {
            return Err(ExecError::SchnorrSig);
        }

        let msg = Message::from_digest_slice(&msg_bytes).map_err(|_| ExecError::SchnorrSig)?;

        let success = self.verify_signature(&sig, &pk, msg)?;

        // BIP 348 requires popping the 3 elements
        self.stack.popn(3)?;

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
    use crate::tests::validate_single_script;

    use bitcoin::{key::Secp256k1, secp256k1};

    use bitcoin_script::script;

    #[test]
    fn test_op_csfs_unknown_key_type_succeeds() {
        let script = script! {
            OP_CHECKSIGFROMSTACK
            { 1 }
            OP_EQUALVERIFY
            { 1 }
        }
        .compile();
        let witness = vec![
            vec![0x01; 64], // Non-empty Sig
            vec![0x00; 32], // Msg
            vec![0xAA; 33], // Unknown PK type (33 bytes)
        ];

        validate_single_script(script, witness).unwrap()
    }

    #[test]
    fn test_op_csfs_empty_sig_pushes_zero() {
        let script = script! {
            OP_CHECKSIGFROMSTACK
            { 0 }
            OP_EQUALVERIFY
            { 1 }
        }
        .compile();
        let witness = vec![
            vec![],         // EMPTY SIG
            vec![0x00; 32], // Msg
            vec![0x01; 32], // PK
        ];

        validate_single_script(script, witness).unwrap()
    }

    #[test]
    fn test_op_csfs_pk_size_zero_fails() {
        let script = script! {
            OP_CHECKSIGFROMSTACK
        }
        .compile();
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
        let script = script! {
            OP_CHECKSIGFROMSTACK
        }
        .compile();
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

        let script = script! {
            OP_CHECKSIGFROMSTACK
            { 1 }
            OP_EQUALVERIFY
            { 1 }
        }
        .compile();

        let witness = vec![
            sig.as_ref().to_vec(),          // <sig>
            msg_bytes.to_vec(),             // <msg>
            x_only_pk.serialize().to_vec(), // <pubkey>
        ];

        validate_single_script(script, witness).expect("Valid Schnorr signature should pass CSFS");
    }
}
