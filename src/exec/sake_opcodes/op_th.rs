//! OP_TEMPLATEHASH [BIP ?](https://github.com/bitcoin/bips/pull/1974/files#bip-templatehash.md)

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, HashEngine, sha256};

use bitcoin::opcodes::all::OP_RETURN_206;
use bitcoin::{Opcode, ScriptBuf};

use crate::exec::{Exec, ExecError};

const TEMPLATEHASH_TAG: &[u8; 32] = &[
    3, 143, 106, 237, 22, 145, 102, 179, 91, 137, 70, 69, 51, 154, 120, 68, 137, 218, 168, 84, 99,
    88, 97, 111, 217, 2, 44, 34, 237, 220, 171, 121,
];

pub const OP_CODE: Opcode = OP_RETURN_206;

#[allow(non_snake_case)]
pub fn OP_TEMPLATEHASH() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CODE.to_u8()])
}
#[allow(non_snake_case)]
pub fn OP_TH() -> ScriptBuf {
    OP_TEMPLATEHASH()
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_th(&mut self) -> Result<(), ExecError> {
        let template_hash = calculate_template_hash(
            self.sighashcache.transaction(),
            self.input_idx,
            // Annex is always disabled in SAKE emulation
            None,
        );

        self.stack.pushstr(template_hash.as_byte_array());

        Ok(())
    }
}

fn calculate_template_hash(
    tx: &Transaction,
    input_index: usize,
    annex: Option<&[u8]>,
) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    // 1. Add Tagged Hash prefix
    engine.input(TEMPLATEHASH_TAG);
    engine.input(TEMPLATEHASH_TAG);

    // 2. Transaction Data
    engine.input(&tx.version.0.to_le_bytes());
    engine.input(&tx.lock_time.to_consensus_u32().to_le_bytes());

    // TODO: reuse sha_sequences from SighashCache
    // when/if rust_bitcoin expose that api

    // Copied from rust bitcoin [SighashCache::common_cache_minimal_borrow]
    {
        let mut enc_sequences = sha256::Hash::engine();
        for txin in tx.input.iter() {
            txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
        }
        engine.input(sha256::Hash::from_engine(enc_sequences).as_ref());

        // sha_outputs (Precomputed by BIP341 logic)
        let mut enc = sha256::Hash::engine();
        for txout in tx.output.iter() {
            txout.consensus_encode(&mut enc).unwrap();
        }
        engine.input(sha256::Hash::from_engine(enc).as_ref());
    }

    // 3. Data about this input
    let annex_present: u8 = if annex.is_some() { 1 } else { 0 };
    engine.input(&[annex_present]);
    engine.input(&(input_index as u32).to_le_bytes());

    // 4. Optional Annex
    if let Some(annex_data) = annex {
        let sha_annex = sha256::Hash::hash(annex_data);
        engine.input(&sha_annex[..]);
    }

    sha256::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {

    use bitcoin::{ScriptBuf, TxOut, consensus::deserialize, sighash::SighashCache};
    use serde::Deserialize;

    use bitcoin_script::{define_pushable, script};
    define_pushable!();

    use crate::tests::validate_single_script;

    use super::*;

    #[derive(Deserialize)]
    struct TestVector {
        spent_outputs: Vec<String>,
        spending_tx: String,
        input_index: usize,
        // expected_template_hash: String,
        valid: bool,
        comment: String,
    }

    #[test]
    fn test_op_templatehash_basic() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/exec/sake_opcodes/op_th/basic.json");
        let file = std::fs::read(path).unwrap();

        let vectors: Vec<TestVector> =
            serde_json::from_slice(&file).expect("Failed to parse test vectors JSON");

        for (i, tv) in vectors.iter().enumerate() {
            println!("Running test {}: {}", i, tv.comment);

            // Parse spending transaction
            let tx_bytes = hex::decode(&tv.spending_tx).expect("Invalid spending_tx hex");
            let tx: Transaction = deserialize(&tx_bytes).expect("Failed to parse spending_tx");

            let mut prevouts = vec![];

            // Parse spent_outputs (not strictly needed for hash, but good for validation)
            for (j, out_hex) in tv.spent_outputs.iter().enumerate() {
                let out_bytes = hex::decode(out_hex).expect("Invalid spent_outputs hex");
                let txout: TxOut = deserialize(&out_bytes).unwrap_or_else(|_| {
                    panic!("Failed to parse spent_outputs[{i}] in test {j}");
                });
                prevouts.push(txout);
            }

            // Extract witness for the input
            assert!(tv.input_index < tx.input.len(), "input_index out of bounds");
            let witness = &tx.input[tv.input_index].witness;

            // Ignore annex vectors
            if witness.len() >= 2 {
                let last = witness.last().unwrap();
                if !last.is_empty() && last[0] == 0x50 {
                    continue;
                }
            };

            let basic_script = ScriptBuf::from_bytes(witness.to_vec().first().cloned().unwrap());

            let mut sighashcache = SighashCache::new(tx);

            let mut exec = Exec::new(
                &mut sighashcache,
                &prevouts,
                tv.input_index,
                // The basic script
                &basic_script,
                // no witness in basic scripts
                vec![],
            )
            .unwrap();

            loop {
                match exec.exec_next() {
                    Ok(_) => continue,
                    Err(err) => {
                        if tv.valid {
                            assert_eq!(err, ExecError::NoMoreInstructions { success: true });
                        } else {
                            assert_eq!(err, ExecError::NoMoreInstructions { success: false });
                        }
                        break;
                    }
                }
            }
        }
    }

    #[derive(Deserialize, Debug, Clone)]
    pub struct ScriptAssetsTestVector {
        #[serde(rename = "tx")]
        pub spending_tx: String,
        #[serde(rename = "prevouts")]
        pub spent_outputs: Vec<String>,
        #[serde(rename = "index")]
        pub input_index: usize,
        // #[serde(deserialize_with = "deserialize_flags")]
        // pub flags: HashSet<ScriptFlag>,
        pub comment: String,
        // #[serde(rename = "final")]
        // pub is_final: bool,
        pub success: WitnessData,
        pub failure: Option<WitnessData>,
    }

    #[derive(Deserialize, Debug, Clone)]
    pub struct WitnessData {
        pub witness: Vec<String>,
    }

    #[test]
    fn test_op_templatehash_script_assets() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/exec/sake_opcodes/op_th/script_assets_test.json");
        let file = std::fs::read(path).unwrap();

        let vectors: Vec<ScriptAssetsTestVector> =
            serde_json::from_slice(&file).expect("Failed to parse test vectors JSON");

        for (i, tv) in vectors.iter().enumerate() {
            println!("Running test {}: {}", i, tv.comment);

            // Parse spending transaction
            let tx_bytes = hex::decode(&tv.spending_tx).expect("Invalid spending_tx hex");
            let tx: Transaction = deserialize(&tx_bytes).expect("Failed to parse spending_tx");

            let mut prevouts = vec![];

            // Parse spent_outputs (not strictly needed for hash, but good for validation)
            for (j, out_hex) in tv.spent_outputs.iter().enumerate() {
                let out_bytes = hex::decode(out_hex).expect("Invalid spent_outputs hex");
                let txout: TxOut = deserialize(&out_bytes).unwrap_or_else(|_| {
                    panic!("Failed to parse spent_outputs[{i}] in test {j}");
                });
                prevouts.push(txout);
            }

            // Extract witness for the input
            assert!(tv.input_index < tx.input.len(), "input_index out of bounds");

            let mut sighashcache = SighashCache::new(tx);

            // Success
            {
                let witness = tv
                    .success
                    .witness
                    .iter()
                    .map(|e| hex::decode(e).unwrap())
                    .collect::<Vec<_>>();

                // Ignore annex vectors
                if witness.len() >= 2 {
                    let last = witness.last().unwrap();
                    if !last.is_empty() && last[0] == 0x50 {
                        continue;
                    }
                };

                // For some reason these test vectors don't have control block
                let script_index = if prevouts[tv.input_index].script_pubkey.is_p2tr() {
                    witness.len().checked_sub(2).unwrap_or_default()
                } else {
                    // segwit
                    witness.len().checked_sub(1).unwrap_or_default()
                };

                let script = ScriptBuf::from_bytes(if witness.is_empty() {
                    vec![]
                } else {
                    witness[script_index].clone()
                });
                let witness_stack = witness[0..script_index].to_vec();

                let mut exec = Exec::new(
                    &mut sighashcache,
                    &prevouts,
                    tv.input_index,
                    // The basic script
                    &script,
                    witness_stack,
                )
                .unwrap();

                loop {
                    match exec.exec_next() {
                        Ok(_) => continue,
                        Err(err) => {
                            if tv.comment == "discouraged_template/emptystack" {
                                // returns an empty stack
                                assert_eq!(err, ExecError::NoMoreInstructions { success: false });
                            } else if script.is_empty() && witness.is_empty() {
                                assert_eq!(err, ExecError::NoMoreInstructions { success: false });
                            } else {
                                assert_eq!(err, ExecError::NoMoreInstructions { success: true });
                            }
                            break;
                        }
                    }
                }
            }

            // Failure
            if let Some(failure) = tv.failure.clone() {
                let witness = failure
                    .witness
                    .iter()
                    .map(|e| hex::decode(e).unwrap())
                    .collect::<Vec<_>>();

                // Ignore annex vectors
                if witness.len() >= 2 {
                    let last = witness.last().unwrap();
                    if !last.is_empty() && last[0] == 0x50 {
                        continue;
                    }
                };

                // For some reason these test vectors don't have control block
                let script_index = if prevouts[tv.input_index].script_pubkey.is_p2tr() {
                    witness.len().checked_sub(2).unwrap_or_default()
                } else {
                    // segwit
                    witness.len().checked_sub(1).unwrap_or_default()
                };

                let script = ScriptBuf::from_bytes(if witness.is_empty() {
                    vec![]
                } else {
                    witness[script_index].clone()
                });
                let witness_stack = witness[0..script_index].to_vec();

                let mut exec = Exec::new(
                    &mut sighashcache,
                    &prevouts,
                    tv.input_index,
                    // The basic script
                    &script,
                    witness_stack,
                )
                .unwrap();

                loop {
                    match exec.exec_next() {
                        Ok(_) => continue,
                        Err(err) => {
                            if tv.comment == "template/32bytes" {
                                assert_eq!(err, ExecError::EqualVerify);
                            } else {
                                assert_eq!(err, ExecError::NoMoreInstructions { success: false });
                            }

                            break;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_valid_templatehash() {
        let templatehash =
            hex::decode("e59457bfc8e4493279a98ec1efc7cc29506440a5490a28fe0737b34dd458e258")
                .unwrap();

        let script = script! {
            OP_TEMPLATEHASH
            <templatehash>
            OP_EQUALVERIFY
            < 1 >
        };
        let witness = vec![];

        validate_single_script(script, witness).unwrap();
    }

    #[test]
    fn test_invalid_templatehash() {
        let templatehash =
            hex::decode("e59457bfc8e4493279a98ec1efc7cc29506440a5490a28fe0737b34dd458e259")
                .unwrap();

        let script = script! {
            OP_TEMPLATEHASH
            <templatehash>
            OP_EQUALVERIFY
            < 1 >
        };
        let witness = vec![];

        assert!(validate_single_script(script, witness).is_err());
    }
}
