//! OP_CAT [BIP 347](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)

use bitcoin::constants::MAX_SCRIPT_ELEMENT_SIZE;

use crate::{Exec, exec::ExecError};

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_cat(&mut self) -> Result<(), ExecError> {
        // (x1 x2 -- x1|x2)
        let x2 = self.stack.popstr()?;
        let x1 = self.stack.popstr()?;
        let ret: Vec<u8> = x1.into_iter().chain(x2).collect();
        if ret.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ExecError::PushSize);
        }
        self.stack.pushstr(&ret);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, exec::ExecError, tests::validate_single_script};

    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    #[test]
    fn test_op_cat_success() {
        let script = script! {
            <"world">
            OP_CAT
            <"hello world">
            OP_EQUAL
        };
        let witness = vec![b"hello ".to_vec()];

        validate_single_script(script, witness).unwrap();
    }

    #[test]
    fn test_op_cat_empty_strings() {
        // Test with one empty string
        let script = script! {
            <""> OP_CAT
            <"bitcoin"> OP_EQUAL
        };

        validate_single_script(script, vec![b"bitcoin".to_vec()]).unwrap();

        // Test with two empty strings
        let script = script! {
            <""> OP_CAT
            <""> OP_EQUAL
        };
        let witness = vec![vec![]];

        validate_single_script(script, witness).unwrap();
    }

    #[test]
    fn test_op_cat_at_max_limit() {
        // 260 bytes + 260 bytes = 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
        let x1 = b"a".repeat(260);
        let x2 = b"b".repeat(260);

        let script = script! {
            <x2> OP_CAT
            OP_DROP
            < 1 >
        };
        let witness = vec![x1];

        validate_single_script(script, witness).unwrap();
    }

    #[test]
    fn test_op_cat_exceed_max_limit() {
        // 260 bytes + 260 bytes = 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
        let x1 = b"a".repeat(260);
        let x2 = b"b".repeat(261);

        let script = script! {
            <x2> OP_CAT
            OP_DROP
            < 1 >
        };
        let witness = vec![x1];

        let result = validate_single_script(script, witness);

        assert!(matches!(result, Err(Error::Exec(ExecError::PushSize))))
    }

    #[test]
    fn test_op_cat_stack_underflow() {
        // Only 1 element on stack
        let script = script! {
            <"lonely"> OP_CAT
            OP_DROP
            < 1 >
        };
        let witness = vec![];

        let result = validate_single_script(script, witness);
        assert!(matches!(
            result,
            Err(Error::Exec(ExecError::InvalidStackOperation))
        ))
    }
}
