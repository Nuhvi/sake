//! OP_SUPPORTSSAKE checks if the interpreter supports SAKE

use bitcoin::{Opcode, opcodes::all::OP_NOP10};

pub const OP_ACTIVATED: Opcode = OP_NOP10;

use crate::{Exec, exec::ExecError};

pub mod flags {
    pub const CAT: i64 = 0b0000_0001;
    pub const CSFS: i64 = 0b0000_0010;

    pub const ALL: i64 = CAT | CSFS;
}

const SUPPORTED_MASK: i64 = flags::ALL;

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn handle_op_activated(&mut self) -> Result<(), ExecError> {
        // Nop
        if !self.supports_sake {
            return Ok(());
        }

        // TODO: support validation with specific flags enabled/disabled?

        // Handle features flag if present (OP_0 preceded by a number)
        if let Ok(flags) = self.stack.popnum()
            && (flags & !SUPPORTED_MASK) != 0
        {
            // Some opcodes are not supported
            // Act as nop
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

    use crate::{
        flags,
        tests::{
            mock_signed_message, validate_single_script, validate_single_script_no_sake_support,
        },
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
        let witness = vec![];

        validate_single_script(script.clone(), witness.clone()).unwrap();
        assert!(validate_single_script_no_sake_support(script, witness).is_err());
    }

    #[test]
    fn test_op_sakesupported_basic() {
        let sake_script = sake_script();

        let script = script! {
            // CTLV and CSV are OP_NOPs in the emulator.
            // So they have to happen before the OP_IF
            { 100 }
            OP_CSV
            OP_DROP

            { flags::ALL }
            OP_ACTIVATED
            OP_1
            OP_EQUAL
            OP_IF
                { sake_script } // Emulate a SAKE script with SAKE opcodes
            OP_ELSE
                // In practice you would check oracles signatures here
                // with OP_CHECKSIG or OP_CHECKSIGADD.
                { 1 }
            OP_ENDIF
        }
        .compile();

        let witness = vec![];

        validate_single_script(script.clone(), witness.clone()).unwrap();
        validate_single_script_no_sake_support(script, witness).unwrap();
    }
}
