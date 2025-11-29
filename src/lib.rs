pub struct TxContext {}

pub enum StackElement {
    OpCode(u8),
}

impl From<&StackElement> for bool {
    fn from(value: &StackElement) -> Self {
        match value {
            StackElement::OpCode(u8) => match u8 {
                0 => false,
                1 => true,
                _ => todo!("cast to bool"),
            },
        }
    }
}

pub fn validate(_context: impl Into<TxContext>, _input: u32, script: Vec<StackElement>) -> bool {
    if script.is_empty() {
        return false;
    } else if script.len() > 1000 {
        return false;
    } else if script.len() == 1 {
        return (&script[0]).into();
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_world() {
        assert!(validate(TxContext {}, 0, vec![StackElement::OpCode(01)]));
    }
}
