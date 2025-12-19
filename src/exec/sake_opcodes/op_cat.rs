use bitcoin::constants::MAX_SCRIPT_ELEMENT_SIZE;

use crate::{Exec, exec::ExecError};

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn handle_op_cat(&mut self) -> Result<(), ExecError> {
        // (x1 x2 -- x1|x2)
        self.stack.needn(2)?;
        let x2 = self.stack.popstr().unwrap();
        let x1 = self.stack.popstr().unwrap();
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
    use bitcoin_script::script;

    use crate::{
        Error,
        exec::{ExecError, sake_opcodes::tests::validate_single_script},
    };

    #[test]
    fn test_op_cat_success() {
        let script = script! {
            {b"hello ".to_vec()}
            {b"world".to_vec()}
            OP_CAT
            {b"hello world".to_vec()}
            OP_EQUAL
        }
        .compile();

        validate_single_script(script, vec![]).unwrap();
    }

    #[test]
    fn test_op_cat_empty_strings() {
        // Test with one empty string
        let script = script! {
            {b"bitcoin".to_vec()}
            {b"".to_vec()}
            OP_CAT
            {b"bitcoin".to_vec()}
            OP_EQUAL
        }
        .compile();

        validate_single_script(script, vec![]).unwrap();

        // Test with two empty strings
        let script = script! {
            {b"".to_vec()}
            {b"".to_vec()}
            OP_CAT
            {b"".to_vec()}
            OP_EQUAL
        }
        .compile();

        validate_single_script(script, vec![]).unwrap();
    }

    #[test]
    fn test_op_cat_at_max_limit() {
        // 260 bytes + 260 bytes = 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
        let x1 = b"a".repeat(260);
        let x2 = b"b".repeat(260);

        let script = script! {
            {x1}
            {x2}
            OP_CAT
            OP_DROP
            { 1 }
        }
        .compile();

        validate_single_script(script, vec![]).unwrap();
    }

    #[test]
    fn test_op_cat_exceed_max_limit() {
        // 260 bytes + 260 bytes = 520 bytes (MAX_SCRIPT_ELEMENT_SIZE)
        let x1 = b"a".repeat(260);
        let x2 = b"b".repeat(261);

        let script = script! {
            {x1}
            {x2}
            OP_CAT
            OP_DROP
            { 1 }
        }
        .compile();

        let result = validate_single_script(script, vec![]);

        assert!(matches!(result, Err(Error::Exec(ExecError::PushSize))))
    }

    #[test]
    fn test_op_cat_stack_underflow() {
        // Only 1 element on stack
        let script = script! {
            {b"lonely".to_vec()}
            OP_CAT
            OP_DROP
            { 1 }
        }
        .compile();

        let result = validate_single_script(script, vec![]);
        assert!(matches!(
            result,
            Err(Error::Exec(ExecError::InvalidStackOperation))
        ))
    }
}
