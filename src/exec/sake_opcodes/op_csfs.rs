//! OP_CHECKSIGFROMSTACK [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)

use bitcoin::{Opcode, ScriptBuf, opcodes::all::OP_RETURN_204};

use crate::{Exec, exec::ExecError};

pub(crate) const OP_CODE: Opcode = OP_RETURN_204;

/// Returns the `OP_CHECKSIGFROMSTACK` opcode as a one-byte script.
#[allow(non_snake_case)]
#[must_use]
pub fn OP_CHECKSIGFROMSTACK() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CODE.to_u8()])
}

/// Returns the `OP_CSFS` opcode as a one-byte script.
///
/// This function is an alias for [`OP_CHECKSIGFROMSTACK`].
#[allow(non_snake_case)]
#[must_use]
pub fn OP_CSFS() -> ScriptBuf {
    OP_CHECKSIGFROMSTACK()
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_csfs(&mut self) -> Result<(), ExecError> {
        // Stack: <sig> <msg> <pubkey> (Top is pubkey)
        let pk = self.stack.popstr()?;
        let msg_bytes = self.stack.popstr()?;
        let sig = self.stack.popstr()?;

        let bool = self.verify_signature(&sig, &pk, &msg_bytes)?;

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

    use std::str::FromStr;

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
    fn test_op_csfs_arbitrary_message_lengths() {
        // BIP-348 has no dedicated vector file. These are the official BIP-340
        // test vectors for 0, 1, 17 and 100 byte messages; BIP-348 verifies the
        // raw message, so all of these must succeed.
        use bitcoin::XOnlyPublicKey;

        let pk = XOnlyPublicKey::from_str(
            "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
        )
        .unwrap();
        let vectors = [
            (
                "",
                "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
            ),
            (
                "11",
                "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
            ),
            (
                "0102030405060708090A0B0C0D0E0F1011",
                "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
            ),
            (
                "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
                "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
            ),
        ];

        for (msg_hex, sig_hex) in vectors {
            let msg = hex::decode(msg_hex).unwrap();
            let sig = hex::decode(sig_hex).unwrap();
            let script = script! {
                { pk }
                OP_CHECKSIGFROMSTACK
            };
            validate_single_script(script, vec![sig, msg]).unwrap();
        }
    }

    #[test]
    fn test_op_csfs_valid_sig_succeeds() {
        let secp = Secp256k1::new();
        let (pk, msg, sig) = mock_signed_message(&secp);

        let script = script! {
            <pk>
            OP_CHECKSIGFROMSTACK
        };

        let witness = vec![
            sig.to_vec(), // <sig>
            msg.to_vec(), // <msg>
        ];

        validate_single_script(script, witness).expect("Valid Schnorr signature should pass CSFS");
    }
}
