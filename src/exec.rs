use bitcoin::secp256k1;
use core::cmp;

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, hash160, ripemd160, sha1, sha256, sha256d};
use bitcoin::opcodes::{Opcode, all::*};
use bitcoin::script::{self, Instruction, Script};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, TapLeafHash};
use bitcoin::transaction::{Transaction, TxOut};

pub use crate::error::{Error, ExecError};
pub use crate::stack::{ConditionStack, Stack};

mod op_checksig;
mod sake_opcodes {
    pub mod op_cat;
    pub mod op_csfs;
}

pub use sake_opcodes::op_csfs::OP_CHECKSIGFROMSTACK;

/// Maximum number of bytes pushable to the stack
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of values on script interpreter stack
const MAX_STACK_SIZE: usize = 1000;

/// How much weight budget is added to the witness size (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Validation weight per passing signature (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub success: bool,
    pub error: Option<ExecError>,
    pub opcode: Option<Opcode>,
    pub final_stack: Stack,
}

impl ExecutionResult {
    fn from_final_stack(final_stack: Stack) -> ExecutionResult {
        ExecutionResult {
            success: if final_stack.len() != 1 {
                false
            } else {
                script::read_scriptbool(&final_stack.last().unwrap())
            },
            final_stack,
            error: None,
            opcode: None,
        }
    }
}

/// Partial execution of a script.
pub struct Exec<'a, 'b> {
    prevouts: &'a [TxOut],
    input_idx: usize,
    leaf_hash: TapLeafHash,

    pub(crate) result: Option<ExecutionResult>,

    sighashcache: &'b mut SighashCache<&'a Transaction>,
    script: &'a Script,
    // Store the instruction position manually instead of keeping an iterator
    instruction_position: usize,
    current_position: usize,
    cond_stack: ConditionStack,
    stack: Stack,
    altstack: Stack,

    validation_weight: i64,

    secp: secp256k1::Secp256k1<secp256k1::All>,
}

impl<'a, 'b> Exec<'a, 'b> {
    pub fn new(
        sighashcache: &'b mut SighashCache<&'a Transaction>,
        prevouts: &'a [TxOut],
        input_idx: usize,
        script: &'a Script,
        script_witness: Vec<Vec<u8>>,
    ) -> Result<Exec<'a, 'b>, Error> {
        // We want to make sure the script is valid so we don't have to throw parsing errors
        // while executing.
        let instructions = script.instructions_minimal();
        if let Some(err) = instructions.clone().find_map(|res| res.err()) {
            return Err(Error::InvalidScript(err));
        }

        //TODO(stevenroose) make this more efficient
        let witness_size =
            Encodable::consensus_encode(&script_witness, &mut bitcoin::io::sink()).unwrap();
        let start_validation_weight = VALIDATION_WEIGHT_OFFSET + witness_size as i64;

        let leaf_hash = TapLeafHash::from_script(
            Script::from_bytes(script.as_bytes()),
            taproot::LeafVersion::TapScript,
        );

        Ok(Exec {
            prevouts,
            input_idx,
            leaf_hash,

            result: None,

            sighashcache,
            script,
            instruction_position: 0,
            current_position: 0,
            cond_stack: ConditionStack::default(),
            //TODO(stevenroose) does this need to be reversed?
            stack: Stack::from_u8_vec(script_witness),
            altstack: Stack::new(),
            validation_weight: start_validation_weight,

            secp: secp256k1::Secp256k1::new(),
        })
    }

    ///////////////
    // EXECUTION //
    ///////////////

    /// Returns true when execution is done.
    pub fn exec_next(&mut self) -> Result<(), &ExecutionResult> {
        if let Some(ref res) = self.result {
            return Err(res);
        }

        // Get the next instruction from the remaining script
        let remaining = &self.script[self.instruction_position..];
        let mut instructions = remaining.instructions_minimal();

        self.current_position = self.instruction_position;
        let instruction = match instructions.next() {
            Some(Ok(i)) => {
                // Update position for next iteration
                self.instruction_position = self.script.len() - instructions.as_script().len();
                i
            }
            None => {
                let res = ExecutionResult::from_final_stack(self.stack.clone());
                self.result = Some(res);
                return Err(self.result.as_ref().unwrap());
            }
            Some(Err(_)) => unreachable!("we checked the script beforehand"),
        };

        let exec = self.cond_stack.all_true();
        match instruction {
            Instruction::PushBytes(p) => {
                if p.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return self.fail(ExecError::PushSize);
                }
                if exec {
                    self.stack.pushstr(p.as_bytes());
                }
            }
            Instruction::Op(op) => {
                // Some things we do even when we're not executing.

                match op {
                    OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
                    | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                        return self.failop(ExecError::DisabledOpcode, op);
                    }
                    OP_RESERVED => {
                        return self.failop(ExecError::Debug, op);
                    }

                    _ => {}
                }

                if (exec || (op.to_u8() >= OP_IF.to_u8() && op.to_u8() <= OP_ENDIF.to_u8()))
                    && let Err(err) = self.exec_opcode(op)
                {
                    return self.failop(err, op);
                }
            }
        }

        Ok(())
    }

    fn exec_opcode(&mut self, op: Opcode) -> Result<(), ExecError> {
        let exec = self.cond_stack.all_true();

        // Remember to leave stack intact until all errors have occurred.
        match op {
            //
            // Push value
            OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4
            | OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9
            | OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
            | OP_PUSHNUM_15 | OP_PUSHNUM_16 => {
                let n = op.to_u8() - (OP_PUSHNUM_1.to_u8() - 2);
                self.stack.pushnum((n as i64) - 1);
            }

            // OP_CTLV and OP_CSV are noop
            OP_NOP | OP_NOP1 | OP_CLTV | OP_CSV | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7
            | OP_NOP8 | OP_NOP10 => {
                // nops
            }

            // OP_CHECKSIGFROMSTACK [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)
            OP_CHECKSIGFROMSTACK => self.handle_op_csfs()?,

            //
            // Control
            OP_IF | OP_NOTIF => {
                if exec {
                    let top = self.stack.topstr(-1)?;

                    // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                    // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                    // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                    if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                        return Err(ExecError::TapscriptMinimalIf);
                    }

                    let b = if op == OP_NOTIF {
                        !script::read_scriptbool(&top)
                    } else {
                        script::read_scriptbool(&top)
                    };
                    self.stack.pop()?;
                    self.cond_stack.push(b);
                } else {
                    self.cond_stack.push(false);
                }
            }

            OP_ELSE => {
                if !self.cond_stack.toggle_top() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_ENDIF => {
                if !self.cond_stack.pop() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_VERIFY => {
                let top = self.stack.topstr(-1)?;

                if !script::read_scriptbool(&top) {
                    return Err(ExecError::Verify);
                } else {
                    self.stack.pop()?;
                }
            }

            OP_RETURN => return Err(ExecError::OpReturn),

            //
            // Stack operations
            OP_TOALTSTACK => {
                let top = self.stack.pop()?;
                self.altstack.push(top);
            }

            OP_FROMALTSTACK => {
                let top = self.altstack.pop()?;
                self.stack.push(top);
            }

            OP_2DROP => {
                // (x1 x2 -- )
                self.stack.needn(2)?;
                self.stack.popn(2).unwrap();
            }

            OP_2DUP => {
                // (x1 x2 -- x1 x2 x1 x2)
                let x1 = self.stack.top(-2)?.clone();
                let x2 = self.stack.top(-1)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_3DUP => {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                let x1 = self.stack.top(-3)?.clone();
                let x2 = self.stack.top(-2)?.clone();
                let x3 = self.stack.top(-1)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
                self.stack.push(x3);
            }

            OP_2OVER => {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x1 = self.stack.top(-4)?.clone();
                let x2 = self.stack.top(-3)?.clone();
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.stack.needn(6)?;
                let x6 = self.stack.pop()?;
                let x5 = self.stack.pop()?;
                let x4 = self.stack.pop()?;
                let x3 = self.stack.pop()?;
                let x2 = self.stack.pop()?;
                let x1 = self.stack.pop()?;
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x5);
                self.stack.push(x6);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2SWAP => {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x4 = self.stack.pop()?;
                let x3 = self.stack.pop()?;
                let x2 = self.stack.pop()?;
                let x1 = self.stack.pop()?;
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_IFDUP => {
                // (x - 0 | x x)
                let top = self.stack.topstr(-1)?;
                if script::read_scriptbool(&top) {
                    self.stack.push(self.stack.top(-1)?.clone());
                }
            }

            OP_DEPTH => {
                // -- stacksize
                self.stack.pushnum(self.stack.len() as i64);
            }

            OP_DROP => {
                // (x -- )
                self.stack.pop()?;
            }

            OP_DUP => {
                // (x -- x x)
                let top = self.stack.top(-1)?.clone();
                self.stack.push(top);
            }

            OP_NIP => {
                // (x1 x2 -- x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop()?;
                self.stack.pop()?;
                self.stack.push(x2);
            }

            OP_OVER => {
                // (x1 x2 -- x1 x2 x1)
                let under_top = self.stack.top(-2)?.clone();
                self.stack.push(under_top);
            }

            OP_PICK | OP_ROLL => {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                let x = self.stack.topnum(-1)?;
                if x < 0 || x >= self.stack.len() as i64 {
                    return Err(ExecError::InvalidStackOperation);
                }
                self.stack.pop()?;
                let elem = self.stack.top(-x as isize - 1).unwrap().clone();
                if op == OP_ROLL {
                    self.stack.remove(self.stack.len() - x as usize - 1);
                }
                self.stack.push(elem);
            }

            OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.stack.needn(3)?;
                let x3 = self.stack.pop()?;
                let x2 = self.stack.pop()?;
                let x1 = self.stack.pop()?;
                self.stack.push(x2);
                self.stack.push(x3);
                self.stack.push(x1);
            }

            OP_SWAP => {
                // (x1 x2 -- x2 x1)
                self.stack.needn(2)?;
                let x2 = self.stack.pop()?;
                let x1 = self.stack.pop()?;
                self.stack.push(x2);
                self.stack.push(x1);
            }

            OP_TUCK => {
                // (x1 x2 -- x2 x1 x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop()?;
                let x1 = self.stack.pop()?;
                self.stack.push(x2.clone());
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_CAT => self.handle_op_cat()?,

            OP_SIZE => {
                // (in -- in size)
                let top = self.stack.topstr(-1)?;
                self.stack.pushnum(top.len() as i64);
            }

            //
            // Bitwise logic
            OP_EQUAL | OP_EQUALVERIFY => {
                // (x1 x2 - bool)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let equal = x1 == x2;
                if op == OP_EQUALVERIFY && !equal {
                    return Err(ExecError::EqualVerify);
                }
                if op == OP_EQUAL {
                    let item = if equal { 1 } else { 0 };
                    self.stack.pushnum(item);
                }
            }

            //
            // Numeric
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                // (in -- out)
                let x = self.stack.topnum(-1)?;
                let res = match op {
                    OP_1ADD => x
                        .checked_add(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_1SUB => x
                        .checked_sub(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_NEGATE => x.checked_neg().ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_ABS => x.abs(),
                    OP_NOT => (x == 0) as i64,
                    OP_0NOTEQUAL => (x != 0) as i64,
                    _ => unreachable!(),
                };
                self.stack.pop()?;
                self.stack.pushnum(res);
            }

            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                // (x1 x2 -- out)
                let x1 = self.stack.topnum(-2)?;
                let x2 = self.stack.topnum(-1)?;
                let res = match op {
                    OP_ADD => x1
                        .checked_add(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_SUB => x1
                        .checked_sub(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_BOOLAND => (x1 != 0 && x2 != 0) as i64,
                    OP_BOOLOR => (x1 != 0 || x2 != 0) as i64,
                    OP_NUMEQUAL => (x1 == x2) as i64,
                    OP_NUMEQUALVERIFY => (x1 == x2) as i64,
                    OP_NUMNOTEQUAL => (x1 != x2) as i64,
                    OP_LESSTHAN => (x1 < x2) as i64,
                    OP_GREATERTHAN => (x1 > x2) as i64,
                    OP_LESSTHANOREQUAL => (x1 <= x2) as i64,
                    OP_GREATERTHANOREQUAL => (x1 >= x2) as i64,
                    OP_MIN => cmp::min(x1, x2),
                    OP_MAX => cmp::max(x1, x2),
                    _ => unreachable!(),
                };
                if op == OP_NUMEQUALVERIFY && res == 0 {
                    return Err(ExecError::NumEqualVerify);
                }
                self.stack.popn(2).unwrap();
                if op != OP_NUMEQUALVERIFY {
                    self.stack.pushnum(res);
                }
            }

            OP_WITHIN => {
                // (x min max -- out)
                let x1 = self.stack.topnum(-3)?;
                let x2 = self.stack.topnum(-2)?;
                let x3 = self.stack.topnum(-1)?;
                self.stack.popn(3).unwrap();
                let res = x2 <= x1 && x1 < x3;
                let item = if res { 1 } else { 0 };
                self.stack.pushnum(item);
            }

            //
            // Crypto

            // (in -- hash)
            OP_RIPEMD160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(ripemd160::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_SHA1 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha1::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_SHA256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha256::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_HASH160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(hash160::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_HASH256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha256d::Hash::hash(&top[..]).to_byte_array().as_ref());
            }

            OP_CODESEPARATOR => {
                // nop
            }

            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                let sig = self.stack.topstr(-2)?.clone();
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.verify_transaction_signature(&sig, &pk)?;
                self.stack.popn(2).unwrap();
                if op == OP_CHECKSIGVERIFY && !res {
                    return Err(ExecError::CheckSigVerify);
                }
                if op == OP_CHECKSIG {
                    let ret = if res { 1 } else { 0 };
                    self.stack.pushnum(ret);
                }
            }

            OP_CHECKSIGADD => {
                let sig = self.stack.topstr(-3)?.clone();
                let mut n = self.stack.topnum(-2)?;
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.verify_transaction_signature(&sig, &pk)?;
                self.stack.popn(3).unwrap();
                if res {
                    n += 1;
                }
                self.stack.pushnum(n);
            }

            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                return Err(ExecError::TapscriptCheckMultiSig);
            }

            // remainder
            _ => return Err(ExecError::BadOpcode),
        }

        if self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
            return Err(ExecError::StackSize);
        }

        Ok(())
    }

    ///////////////
    // UTILITIES //
    ///////////////

    fn fail(&mut self, err: ExecError) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: None,
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn failop(&mut self, err: ExecError, op: Opcode) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: Some(op),
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }
}

/// Decodes an integer in script format with flexible size limit.
///
/// Note that in the majority of cases, you will want to use
/// [`read_scriptint`] instead.
///
/// Panics if max_size exceeds 8.
pub fn read_scriptint_size(v: &[u8], max_size: usize) -> Result<i64, script::Error> {
    assert!(max_size <= 8);

    if v.len() > max_size {
        return Err(script::Error::NumericOverflow);
    }

    if v.is_empty() {
        return Ok(0);
    }

    // require minimal
    {
        let last = match v.last() {
            Some(last) => last,
            None => return Ok(0),
        };
        // Comment and code copied from Bitcoin Core:
        // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (*last & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
                return Err(script::Error::NonMinimalPush);
            }
        }
    }

    Ok(scriptint_parse(v))
}

/// Caller to guarantee that `v` is not empty.
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v
        .iter()
        .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}

pub(crate) fn read_scriptint(item: &[u8], size: usize) -> Result<i64, ExecError> {
    read_scriptint_size(item, size).map_err(|e| match e {
        script::Error::NonMinimalPush => ExecError::MinimalData,
        // only possible if size is 4 or lower
        script::Error::NumericOverflow => ExecError::ScriptIntNumericOverflow,
        // should never happen
        _ => unreachable!(),
    })
}
