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
        // TODO: support non-empty TXFS after the bip has clear ref-impl matching the test vector.
        if !txfs.is_empty() {
            return Err(ExecError::TxHash("Non-empty TXFS is not yet supported!"));
        }

        let tx = self.sighashcache.transaction();
        let prevouts = self.prevouts;
        let current_input_idx = self.input_idx as u32;
        // OP_CODESEPARATOR is disabled
        let current_input_last_codeseparator_pos = None;

        bip_0346::calculate_txhash(
            txfs,
            tx,
            prevouts,
            current_input_idx,
            current_input_last_codeseparator_pos,
        )
        .map_err(ExecError::TxHash)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Transaction, TxOut, consensus::encode::deserialize_hex, hashes::Hash};
    use serde::Deserialize;

    use crate::op_ctv::bip_0346::calculate_txhash;

    #[derive(Debug, Deserialize)]
    struct TestCase {
        tx: String,
        prevs: Vec<String>,
        vectors: Vec<TestVector>,
    }

    #[derive(Debug, Deserialize)]
    struct TestVector {
        id: String,
        txfs: String,
        input: usize,
        codeseparator: Option<u32>,
        txhash: String,
    }

    #[test]
    fn test_op_checktxhashverify() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/exec/sake_opcodes/op_ctv/bip_346_test_vectors.json");
        let file = std::fs::read(path).unwrap();
        let test_cases: Vec<TestCase> = serde_json::from_slice(&file).unwrap();

        let mut failure = vec![];

        for test_case in test_cases {
            let tx: Transaction = deserialize_hex(&test_case.tx).unwrap();
            let prevs: Vec<TxOut> = test_case
                .prevs
                .iter()
                .map(|s| deserialize_hex(s).unwrap())
                .collect();

            for vector in &test_case.vectors {
                let TestVector {
                    id,
                    txfs,
                    input,
                    codeseparator,
                    txhash,
                } = vector;

                let txfs: Vec<u8> = hex::decode(txfs).unwrap();
                let txhash: Vec<u8> = hex::decode(txhash).unwrap();

                // TODO: test more OP_CHECKTXHASHVERIFY TXFSs
                if !txfs.is_empty() {
                    continue;
                }

                let calculated =
                    calculate_txhash(&txfs, &tx, &prevs, *input as u32, *codeseparator).unwrap();

                if calculated.as_byte_array().as_slice() != txhash {
                    failure.push(id.clone());
                    continue;
                }

                assert_eq!(calculated.as_byte_array().as_slice(), &txhash);
            }
        }

        println!("Failures: {:?}", &failure);
        assert!(failure.is_empty())
    }
}
