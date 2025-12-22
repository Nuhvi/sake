use bitcoin::{
    Opcode,
    hashes::{Hash, sha256},
    opcodes::all::OP_NOP4,
};

use crate::{Exec, exec::ExecError};

mod bip_0346;

pub const OP_CHECKTXHASHVERIFY: Opcode = OP_NOP4;
/// OP_CHECKTXHASHVERIFY
pub const OP_CTV: Opcode = OP_CHECKTXHASHVERIFY;

pub use bip_0346::{
    TXFS_CONTROL, TXFS_CURRENT_INPUT_CONTROL_BLOCK, TXFS_CURRENT_INPUT_IDX,
    TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS, TXFS_CURRENT_INPUT_SPENTSCRIPT,
    TXFS_CURRENT_INPUT_TAPROOT_ANNEX, TXFS_INOUT_INDIVIDUAL_MODE, TXFS_INOUT_LEADING_SIZE,
    TXFS_INOUT_NUMBER, TXFS_INOUT_SELECTION_ALL, TXFS_INOUT_SELECTION_CURRENT,
    TXFS_INOUT_SELECTION_MASK, TXFS_INOUT_SELECTION_MODE, TXFS_INOUT_SELECTION_NONE,
    TXFS_INPUTS_ALL, TXFS_INPUTS_PREV_SCRIPTPUBKEYS, TXFS_INPUTS_PREV_VALUES, TXFS_INPUTS_PREVOUTS,
    TXFS_INPUTS_SCRIPTSIGS, TXFS_INPUTS_SEQUENCES, TXFS_INPUTS_TAPROOT_ANNEXES, TXFS_LOCKTIME,
    TXFS_OUTPUTS_ALL, TXFS_OUTPUTS_SCRIPTPUBKEYS, TXFS_OUTPUTS_VALUES, TXFS_SPECIAL_TEMPLATE,
    TXFS_VERSION,
};

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn handle_op_ctv(&mut self) -> Result<(), ExecError> {
        if !self.supports_sake {
            return Ok(());
        }

        // 1. Requirement: At least one element on the stack
        self.stack.needn(1)?;

        // 2. Requirement: If less than 32 bytes, it's a NOP (for forward compatibility)
        let element = self.stack.topstr(-1)?;
        if element.len() < 32 {
            return Ok(());
        }

        // 3. Split into StackTxHash (first 32) and TxFieldSelector (suffix)
        let (stack_tx_hash, txfs) = element.split_at(32);

        // 4. Calculate the transaction hash based on the selector
        let calculated_hash = self.calculate_tx_hash(txfs)?;

        // 5. Verification: Fail if mismatch
        if stack_tx_hash != calculated_hash.as_byte_array() {
            return Err(ExecError::TxHashVerify);
        }

        // CTV does not pop the stack (standard VERIFY behavior for NOP upgrades)
        Ok(())
    }

    fn calculate_tx_hash(&self, txfs: &[u8]) -> Result<sha256::Hash, ExecError> {
        let tx = self.sighashcache.transaction();
        let prevouts = self.prevouts;
        let current_input_idx = self.input_idx as u32;
        // TODO: Consider supporting code separator at least when emulating legacy code.
        let current_input_last_codeseparator_pos = None;

        bip_0346::calculate_txhash(
            txfs,
            tx,
            prevouts,
            current_input_idx,
            current_input_last_codeseparator_pos,
        )
        .map_err(|err| ExecError::TxHash(err.to_string()))
    }
}
