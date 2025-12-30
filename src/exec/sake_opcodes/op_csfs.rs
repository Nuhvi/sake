//! OP_CHECKSIGFROMSTACK [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)

use bitcoin::{Opcode, ScriptBuf, opcodes::all::OP_RETURN_204, secp256k1::Message};

pub(crate) const OP_CODE: Opcode = OP_RETURN_204;

#[allow(non_snake_case)]
pub fn OP_CHECKSIGFROMSTACK() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CODE.to_u8()])
}
#[allow(non_snake_case)]
pub fn OP_CSFS() -> ScriptBuf {
    OP_CHECKSIGFROMSTACK()
}

use crate::{Exec, exec::ExecError};

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_csfs(&mut self) -> Result<(), ExecError> {
        // BIP 348 requires 3 elements
        self.stack.needn(3)?;

        // Stack: <sig> <msg> <pubkey> (Top is pubkey)
        let pk = self.stack.popstr()?;
        let msg_bytes = self.stack.popstr()?;
        let sig = self.stack.popstr()?;

        if msg_bytes.len() != 32 {
            return Err(ExecError::SchnorrSig);
        }

        let msg = Message::from_digest_slice(&msg_bytes).map_err(|_| ExecError::SchnorrSig)?;

        let bool = self.verify_signature(&sig, &pk, msg)?;

        self.stack.pushnum(bool as i64);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Error, OP_CHECKSIGFROMSTACK,
        exec::ExecError,
        tests::{mock_signed_message, validate_single_script},
    };

    use bitcoin::key::Secp256k1;

    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    #[test]
    fn test_op_csfs_unknown_key_type_succeeds() {
        let script = script! {
            OP_CHECKSIGFROMSTACK
        };
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
            OP_0
            OP_EQUAL
        };
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
        };
        let witness = vec![
            vec![0x01; 64],
            vec![0x00; 32],
            vec![], // PK SIZE ZERO
        ];

        let res = validate_single_script(script, witness);

        assert_eq!(
            res,
            Err(Error::Exec(ExecError::PubkeyType)),
            "PK size 0 must fail script"
        );
    }

    #[test]
    fn test_op_csfs_invalid_sig_hard_fail() {
        let script = script! {
            OP_CHECKSIGFROMSTACK
        };
        let witness = vec![
            vec![0xff; 64], // Invalid but non-empty sig
            vec![0x00; 32],
            vec![0x01; 32],
        ];

        let res = validate_single_script(script, witness);

        assert_eq!(
            res,
            Err(Error::Exec(ExecError::SchnorrSig)),
            "Invalid non-empty signature must terminate with error"
        );
    }

    #[test]
    fn test_op_csfs_valid_sig_succeeds() {
        let secp = Secp256k1::new();
        let (pk, msg, sig) = mock_signed_message(&secp);

        let script = script! {
            { pk }
            OP_CHECKSIGFROMSTACK
        };

        let witness = vec![
            sig.to_vec(), // <sig>
            msg.to_vec(), // <msg>
        ];

        validate_single_script(script, witness).expect("Valid Schnorr signature should pass CSFS");
    }
}
