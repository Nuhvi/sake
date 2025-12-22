//! OP_SUPPORTSSAKE checks if the interpreter supports SAKE

use bitcoin::{Opcode, opcodes::all::OP_NOP10};

pub const OP_ACTIVATED: Opcode = OP_NOP10;

use crate::{Exec, exec::ExecError};

pub mod flags {
    // LSB (0000_0001) is disabled

    pub const CAT: u8 = 0b0000_0010;
    pub const CSFS: u8 = 0b0000_0100;

    pub const ALL: u8 = CAT | CSFS;
}

const SUPPORTED_MASK: u8 = flags::ALL;

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn handle_op_activated(&mut self) -> Result<(), ExecError> {
        // Nop
        if !self.supports_sake {
            return Ok(());
        }

        // TODO: support validation with specific flags enabled/disabled?

        let bitflag = self.stack.popnum()? as u8;
        // Ignore LSB because it is disabled
        let bitflag = bitflag & 0b1111_1110;

        self.stack.pushnum((bitflag & !SUPPORTED_MASK == 0) as i64);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{XOnlyPublicKey, key::Secp256k1};
    use bitcoin_script::{Script, script};

    use crate::{
        flags,
        tests::{
            mock_signed_message, validate_single_script, validate_single_script_no_sake_support,
        },
    };

    fn sake_script(pk: XOnlyPublicKey) -> Script {
        script! {
            // Test OP_CAT
            { b"world".to_vec() }
            OP_CAT
            { b"hello world".to_vec() }
            OP_EQUALVERIFY

            // Test OP_CHECKSIGFROMSTACK
            { pk }
            OP_CHECKSIGFROMSTACK
            { 1 }
            OP_EQUALVERIFY

            { 1 }
        }
    }

    #[test]
    fn test_op_activated_fail() {
        let secp = Secp256k1::new();

        let (pk, msg, sig) = mock_signed_message(&secp);

        let script = sake_script(pk).compile();
        let witness = vec![sig.to_vec(), msg.to_vec(), b"hello ".to_vec()];

        validate_single_script(script.clone(), witness.clone()).unwrap();
        assert!(validate_single_script_no_sake_support(script, witness).is_err());
    }

    #[test]
    fn test_op_activated_basic() {
        let secp = Secp256k1::new();
        let (pk, msg, sig) = mock_signed_message(&secp);

        let sake_script = sake_script(pk);

        let script = script! {
            // CTLV and CSV are OP_NOPs in the emulator.
            // So they have to happen before the OP_IF
            { 100 }
            OP_CSV
            OP_DROP

            OP_IF
                { sake_script } // Emulate a SAKE script with SAKE opcodes
            OP_ELSE
                // In practice you would check oracles signatures here
                // with OP_CHECKSIG or OP_CHECKSIGADD.
                { b"legacy".to_vec() }
                OP_EQUAL
            OP_ENDIF
        }
        .compile();

        //  Enable SAKE script by passing an OP_1
        validate_single_script(
            script.clone(),
            vec![sig.to_vec(), msg.to_vec(), b"hello ".to_vec(), vec![1]],
        )
        .expect("valid sak emulation");

        // Disable SAKE script by passing an OP_0 (empty)
        validate_single_script_no_sake_support(script, vec![b"legacy".to_vec(), vec![]])
            .expect("valid legacy exec");
    }
}
