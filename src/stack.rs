use bitcoin::{Witness, script::write_scriptint};
use core::cell::RefCell;
use core::cmp::PartialEq;
use std::rc::Rc;

use crate::exec::{ExecError, read_scriptint};

/// One stack element.
///
/// The emulator keeps numbers in decoded form while they fit in four bytes.
/// Every pushed script value starts as a byte string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StackEntry {
    /// A decoded script number.
    Num(i64),
    /// A shared byte string.
    StrRef(Rc<RefCell<Vec<u8>>>),
}

/// Returns the minimally encoded script number as bytes.
///
/// `i64::MIN` has no 8-byte sign-magnitude encoding, so this function clamps
/// it to `i64::MIN + 1`. Script execution cannot produce that value.
fn scriptint_vec(n: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, n.max(i64::MIN + 1));

    buf.get(..len).map(|s| s.to_vec()).unwrap_or_default()
}

impl StackEntry {
    /// Returns the byte representation of this entry.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            StackEntry::Num(v) => scriptint_vec(*v),
            StackEntry::StrRef(v) => v.borrow().to_vec(),
        }
    }
}

/// Returns true if `v` can be encoded as a minimal 4-byte script number.
///
/// The most negative 4-byte value is `-2^31 + 1`, not `i32::MIN`. Values below
/// it need a 5-byte encoding, which numeric opcodes reject (BIP-342).
fn fits_four_byte_script_num(v: i64) -> bool {
    (-(i32::MAX as i64)..=i32::MAX as i64).contains(&v)
}

/// The script execution stack.
///
/// A negative offset counts from the top: `-1` is the top element.
#[derive(Clone, Debug, Default, Eq)]
pub struct Stack(Vec<StackEntry>);

impl Stack {
    /// Creates an empty stack with room for the BIP-342 element limit.
    pub fn new() -> Self {
        Self(Vec::with_capacity(1000))
    }

    /// Returns the top stack element as bytes.
    pub fn last(&self) -> Result<Vec<u8>, ExecError> {
        self.topstr(-1)
    }

    /// Returns the entry at `offset` from the top of the stack.
    ///
    /// `offset` must be negative. Returns [`ExecError::InvalidStackOperation`]
    /// when the offset is zero, positive, or below the bottom of the stack.
    pub fn top(&self, offset: isize) -> Result<&StackEntry, ExecError> {
        if offset >= 0 {
            return Err(ExecError::InvalidStackOperation);
        }

        self.0
            .len()
            .checked_sub(offset.unsigned_abs())
            .and_then(|index| self.0.get(index))
            .ok_or(ExecError::InvalidStackOperation)
    }

    /// Returns the entry at `offset` from the top of the stack as bytes.
    pub fn topstr(&self, offset: isize) -> Result<Vec<u8>, ExecError> {
        let entry = self.top(offset)?;
        match entry {
            StackEntry::Num(v) => Ok(scriptint_vec(*v)),
            StackEntry::StrRef(v) => Ok(v.borrow().to_vec()),
        }
    }

    /// Returns the entry at `offset` from the top of the stack as a number.
    ///
    /// Fails with [`ExecError::ScriptIntNumericOverflow`] when the number does
    /// not fit in four bytes.
    pub fn topnum(&self, offset: isize) -> Result<i64, ExecError> {
        let entry = self.top(offset)?;
        match entry {
            StackEntry::Num(v) => {
                if fits_four_byte_script_num(*v) {
                    Ok(*v)
                } else {
                    Err(ExecError::ScriptIntNumericOverflow)
                }
            }
            StackEntry::StrRef(v) => Ok(read_scriptint(v.borrow().as_slice(), 4)?),
        }
    }

    /// Pushes a decoded script number.
    pub fn pushnum(&mut self, num: i64) {
        self.0.push(StackEntry::Num(num));
    }

    /// Pushes a byte string.
    pub fn pushstr(&mut self, v: &[u8]) {
        self.0
            .push(StackEntry::StrRef(Rc::new(RefCell::new(v.to_vec()))));
    }

    /// Pushes one entry.
    pub fn push(&mut self, v: StackEntry) {
        self.0.push(v);
    }

    /// Checks that the stack holds at least `min_nb_items` entries.
    pub fn needn(&self, min_nb_items: usize) -> Result<(), ExecError> {
        if self.len() < min_nb_items {
            Err(ExecError::InvalidStackOperation)
        } else {
            Ok(())
        }
    }

    /// Removes `n` entries from the top of the stack.
    pub fn popn(&mut self, n: usize) -> Result<(), ExecError> {
        for _ in 0..n {
            self.0.pop().ok_or(ExecError::InvalidStackOperation)?;
        }
        Ok(())
    }

    /// Removes and returns the top entry.
    pub fn pop(&mut self) -> Result<StackEntry, ExecError> {
        self.0.pop().ok_or(ExecError::InvalidStackOperation)
    }

    /// Removes and returns the top entry as bytes.
    pub fn popstr(&mut self) -> Result<Vec<u8>, ExecError> {
        let entry = self.0.pop().ok_or(ExecError::InvalidStackOperation)?;
        match entry {
            StackEntry::Num(v) => Ok(scriptint_vec(v)),
            StackEntry::StrRef(v) => Ok(v.borrow().to_vec()),
        }
    }

    /// Removes and returns the top entry as a number.
    ///
    /// Fails with [`ExecError::ScriptIntNumericOverflow`] when the number does
    /// not fit in four bytes.
    pub fn popnum(&mut self) -> Result<i64, ExecError> {
        let entry = self.0.pop().ok_or(ExecError::InvalidStackOperation)?;
        match entry {
            StackEntry::Num(v) => {
                if fits_four_byte_script_num(v) {
                    Ok(v)
                } else {
                    Err(ExecError::ScriptIntNumericOverflow)
                }
            }
            StackEntry::StrRef(v) => Ok(read_scriptint(v.borrow().as_slice(), 4)?),
        }
    }

    /// Returns the number of entries on the stack.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when the stack holds no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes and returns the entry at `index`.
    ///
    /// Returns [`ExecError::InvalidStackOperation`] when the index is out of
    /// bounds.
    pub fn remove(&mut self, index: usize) -> Result<StackEntry, ExecError> {
        if index >= self.0.len() {
            return Err(ExecError::InvalidStackOperation);
        }
        Ok(self.0.remove(index))
    }

    /// Builds the stack from a witness.
    pub fn from_witness(w: Witness) -> Self {
        let mut res = Self::new();
        for entry in w.to_vec() {
            res.0.push(StackEntry::StrRef(Rc::new(RefCell::new(entry))));
        }
        res
    }
}

impl PartialEq for Stack {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(other.0.iter())
                .all(|(a, b)| a.as_bytes() == b.as_bytes())
    }
}

/// A wrapper for the stack types to print them in Bitcoin Script ASM format.
impl std::fmt::Display for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut iter = self.0.iter().rev().peekable();
        while let Some(entry) = iter.next() {
            match entry {
                StackEntry::Num(n) => {
                    write!(f, "{n}")?;
                }
                StackEntry::StrRef(v) => {
                    let bytes = v.borrow();
                    if bytes.is_empty() {
                        write!(f, "0")?;
                    } else if let Ok(num) = read_scriptint(bytes.as_slice(), 4) {
                        // Try to interpret as scriptint for cleaner display
                        write!(f, "{num}")?;
                    } else {
                        // Display as raw hex (no 0x prefix, matching Bitcoin Script ASM)
                        for byte in bytes.iter() {
                            write!(f, "{byte:02x}")?;
                        }
                    }
                }
            }
            if iter.peek().is_some() {
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

///  A data type to abstract out the condition stack during script execution.
///
/// Conceptually it acts like a vector of booleans, one for each level of nested
/// IF/THEN/ELSE, indicating whether we're in the active or inactive branch of
/// each.
///
/// The elements on the stack cannot be observed individually; we only need to
/// expose whether the stack is empty and whether or not any false values are
/// present at all. To implement OP_ELSE, a toggle_top modifier is added, which
/// flips the last value without returning it.
///
/// This uses an optimized implementation that does not materialize the
/// actual stack. Instead, it just stores the size of the would-be stack,
/// and the position of the first false value in it.
pub(crate) struct ConditionStack {
    /// The size of the implied stack.
    size: usize,
    /// The position of the first false value on the implied stack,
    /// or NO_FALSE if all true.
    first_false_pos: usize,
}

impl ConditionStack {
    /// A constant for first_false_pos to indicate there are no falses.
    const NO_FALSE: usize = usize::MAX;

    pub(crate) fn new() -> Self {
        Self {
            size: 0,
            first_false_pos: Self::NO_FALSE,
        }
    }

    pub(crate) fn all_true(&self) -> bool {
        self.first_false_pos == Self::NO_FALSE
    }

    /// Returns true when no conditional (OP_IF/OP_NOTIF) is open.
    pub(crate) fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub(crate) fn push(&mut self, v: bool) {
        if self.first_false_pos == Self::NO_FALSE && !v {
            // The stack consists of all true values, and a false is added.
            // The first false value will appear at the current size.
            self.first_false_pos = self.size;
        }
        self.size += 1;
    }

    /// Returns [false] if it was empty, [true] otherwise.
    ///
    /// Note that the popped value is not returned.
    pub(crate) fn pop(&mut self) -> bool {
        if self.size == 0 {
            false
        } else {
            self.size -= 1;
            if self.first_false_pos == self.size {
                // When popping off the first false value, everything becomes true.
                self.first_false_pos = Self::NO_FALSE;
            }
            true
        }
    }

    pub(crate) fn toggle_top(&mut self) -> bool {
        if self.size == 0 {
            false
        } else {
            if self.first_false_pos == Self::NO_FALSE {
                // The current stack is all true values; the first false will be the top.
                self.first_false_pos = self.size - 1;
            } else if self.first_false_pos == self.size - 1 {
                // The top is the first false value; toggling it will make everything true.
                self.first_false_pos = Self::NO_FALSE;
            } else {
                // There is a false value, but not on top. No action is needed as toggling
                // anything but the first false value is unobservable.
            }
            true
        }
    }
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_top_rejects_extreme_offset_without_panic() {
        let stack = Stack::new();
        assert_eq!(stack.top(0), Err(ExecError::InvalidStackOperation));
        assert_eq!(stack.top(isize::MIN), Err(ExecError::InvalidStackOperation));
        assert_eq!(stack.top(-1), Err(ExecError::InvalidStackOperation));
    }

    #[test]
    fn test_remove_out_of_bounds_returns_error() {
        let mut stack = Stack::new();
        assert_eq!(stack.remove(0), Err(ExecError::InvalidStackOperation));

        stack.pushnum(1);
        assert_eq!(stack.remove(0), Ok(StackEntry::Num(1)));
        assert_eq!(stack.remove(0), Err(ExecError::InvalidStackOperation));
    }

    #[test]
    fn test_min_number_encoding_is_total() {
        assert_eq!(scriptint_vec(i64::MIN), scriptint_vec(i64::MIN + 1));
    }
}
