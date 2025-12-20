//! OP_SUPPORTSSAKE checks if the interpreter supports SAKE

use bitcoin::{Opcode, opcodes::all::OP_NOP10};

pub const OP_SAKESUPPORTED: Opcode = OP_NOP10;

use crate::{Exec, exec::ExecError};

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn handle_op_supportssake(&mut self) -> Result<(), ExecError> {
        // Nop
        if !self.supports_sake {
            return Ok(());
        }

        self.stack.pushnum(1);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::key::Secp256k1;
    use bitcoin_script::{Script, script};

    use crate::tests::{
        mock_signed_message, validate_single_script, validate_single_script_no_sake_support,
    };

    fn sake_script() -> Script {
        let secp = Secp256k1::new();
        let (pk, msg, sig) = mock_signed_message(&secp);

        script! {
            // Test OP_CAT
            { b"hello ".to_vec() }
            { b"world".to_vec() }
            OP_CAT
            { b"hello world".to_vec() }
            OP_EQUALVERIFY

            // Test OP_CHECKSIGFROMSTACK

            { sig.to_vec() }
            { msg.to_vec() }
            { pk.to_vec() }
            OP_CHECKSIGFROMSTACK
            { 1 }
            OP_EQUALVERIFY
            { 1 }
        }
    }

    #[test]
    fn test_op_sakesupported_fail() {
        let script = sake_script().compile();
        let witness = vec![
            vec![0x01; 64], // Non-empty Sig
            vec![0x00; 32], // Msg
            vec![0xAA; 33], // Unknown PK type (33 bytes)
        ];

        validate_single_script(script.clone(), witness.clone()).unwrap();
        assert!(validate_single_script_no_sake_support(script, witness).is_err());
    }

    #[test]
    fn test_op_sakesupported_basic() {
        let sake_script = sake_script();

        let script = script! {
            OP_0
            OP_SAKESUPPORTED
            OP_IF
                OP_DROP // Remove the remaining OP_0
                { sake_script } // Emulate a SAKE script with SAKE opcodes
            OP_ELSE
                // In practice you would check oracles signatures here
                // with OP_CHECKSIG or OP_CHECKSIGADD.
                { 1 }
            OP_ENDIF
        }
        .compile();

        let witness = vec![
            vec![0x01; 64], // Non-empty Sig
            vec![0x00; 32], // Msg
            vec![0xAA; 33], // Unknown PK type (33 bytes)
        ];

        validate_single_script(script.clone(), witness.clone()).unwrap();
        validate_single_script_no_sake_support(script, witness).unwrap();
    }
}
