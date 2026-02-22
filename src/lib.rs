//! SAKE Script Army Knife Emulation

#![deny(
    // missing_docs, 
    unused_must_use
)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    // clippy::expect_used,
    clippy::await_holding_lock,
    clippy::indexing_slicing,
    clippy::await_holding_refcell_ref,
    clippy::fallible_impl_from,
    clippy::wildcard_enum_match_arm,
    clippy::unneeded_field_pattern,
    clippy::fn_params_excessive_bools
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use bitcoin::{
    ScriptBuf, Transaction, TxOut,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message, schnorr},
    sighash::{Prevouts, SighashCache},
};

mod error;
mod exec;
mod script_encoding;
mod stack;
mod witness_carrier;

use exec::Exec;

pub use error::Error;
pub use script_encoding::EncodeSakeScript;
pub use witness_carrier::SakeWitnessCarrier;

pub use exec::op_amount::{
    OP_AMOUNT, OP_AMOUNT_CURRENT_INPUT_SELECTOR, OpAmountError, op_amount_input_selector,
    op_amount_output_selector,
};
pub use exec::op_ccv::{OP_CCV, OP_CHECKCONTRACTVERIFY};
pub use exec::op_csfs::{OP_CHECKSIGFROMSTACK, OP_CSFS};
pub use exec::op_th::{OP_TEMPLATEHASH, OP_TH};

use crate::script_encoding::extract_encoded_scripts;

/// Validates SAKE scripts in a transaction.
///
/// - `tx`: The transaction (used to calculate the sighash) and the last output contains the script witnesses as an OP_RETURN
/// - `prevouts`: All the previous [TxOut]s for all the inputs (used to calculate the sighash).
/// - `scripts` : Tuples of (`input index`, `ScriptBuf`) for the inputs to evaluate.
///     - `input_index`: used in sighash calculation.
///     - `ScriptBuf`: locking script for this input, evaluated with the respective script witness defcoded from the last [TxOut] (`OP_RETURN`) in the `tx`.
pub fn validate(
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[(usize, ScriptBuf)],
) -> Result<(), Error> {
    validate_inner(&mut tx.clone(), prevouts, inputs)
}

/// Validates SAKE scripts in a transaction and return signatures over
/// inputs once all spending conditions for all inputs are satisiied.
///
/// - `keypair`: Oracle's Keypair to sign the transaction inputs Sighashes with after validation.
/// - `tx`: The transaction (used to calculate the sighash) and the last output contains the script witnesses as an OP_RETURN
/// - `prevouts`: All the previous [TxOut]s for all the inputs (used to calculate the sighash).
/// - `scripts` : Tuples of (`input index`, `ScriptBuf`) for the inputs to evaluate.
///     - `input_index`: used in sighash calculation.
///     - `ScriptBuf`: locking script for this input, evaluated with the respective script witness defcoded from the last [TxOut] (`OP_RETURN`) in the `tx`.
pub fn validate_and_sign(
    keypair: &Keypair,
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[(usize, ScriptBuf)],
) -> Result<Vec<schnorr::Signature>, Error> {
    let secp = Secp256k1::new();
    validate_and_sign_with_secp(&secp, keypair, tx, prevouts, inputs)
}

/// Validates SAKE scripts in a transaction and return signatures over
/// inputs once all spending conditions for all inputs are satisiied.
///
/// - `secp`: [Secp256k1] context.
/// - `keypair`: Oracle's Keypair to sign the transaction inputs Sighashes with after validation.
/// - `tx`: The transaction (used to calculate the sighash) and the last output contains the script witnesses as an OP_RETURN
/// - `prevouts`: All the previous [TxOut]s for all the inputs (used to calculate the sighash).
/// - `scripts` : Tuples of (`input index`, `ScriptBuf`) for the inputs to evaluate.
///     - `input_index`: used in sighash calculation.
///     - `ScriptBuf`: locking script for this input, evaluated with the respective script witness defcoded from the last [TxOut] (`OP_RETURN`) in the `tx`.
pub fn validate_and_sign_with_secp(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[(usize, ScriptBuf)],
) -> Result<Vec<schnorr::Signature>, Error> {
    let original_tx = tx.clone();
    let mut emulated_tx = tx.clone();

    validate_inner(&mut emulated_tx, prevouts, inputs)?;

    let mut signatures = Vec::with_capacity(inputs.len());

    // Taproot sighashes require knowledge of all prevouts being spent
    let prevouts_all = Prevouts::All(prevouts);

    // sighashcache from the original transaction.
    let mut sighashcache = SighashCache::new(original_tx);

    for (input_idx, _script) in inputs {
        let sighash = sighashcache
            .taproot_key_spend_signature_hash(
                *input_idx,
                &prevouts_all,
                bitcoin::TapSighashType::All,
            )
            .map_err(Error::SigningError)?;

        // Convert hash to SECP256K1 message
        let msg = Message::from_digest(sighash.to_byte_array());

        // Sign with Schnorr
        let sig = secp.sign_schnorr(&msg, keypair);
        signatures.push(sig);
    }

    Ok(signatures)
}

fn validate_inner<'a>(
    tx: &mut Transaction,
    prevouts: &'a [TxOut],
    inputs: &'a [(usize, ScriptBuf)],
) -> Result<(), Error> {
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }

    // Step 1: Extract encoded input scripts
    let inputs: Vec<_> = extract_encoded_scripts(inputs).map_err(Error::InvalidScriptEncoding)?;

    if inputs.is_empty() {
        // If the transaction is not encumbered by SAKE scripts at all,
        // no need to validate it.
        //
        // This is useful in the case of slashable bonds, if the oracle
        // key is used to sign other things than SAKE transactions, for
        // example an Arcade script.
        return Ok(());
    }

    // Step 2: Extract witness stacks from the last output if it's OP_RETURN

    // Remove the witness carrier from the transaction..
    // signatures and introspections will be based on the transaction
    // after removing the witness carrier.
    let last_output = tx.output.pop();

    let witness_stacks = if let Some(last_output) = last_output {
        last_output
            .parse_witness_stacks()
            .map_err(Error::InvalidWitnessCarriers)?
    } else {
        vec![]
    };

    // Step 3: Validate count
    if witness_stacks.len() != inputs.len() {
        return Err(Error::WitnessCountMismatch {
            expected: inputs.len(),
            found: witness_stacks.len(),
        });
    }

    // SighashCache from the transaction without the witness stack.
    //
    // This is because the witness stack may include an introspection of
    // transaction outputs and expects a specific number of outputs and
    // or script pubkeys that wouldn't match after adding the witness carrier
    let mut sighashcache = SighashCache::new(tx.clone());

    // Initialize CCV transaction-wide state (BIP-443)
    let ccv_tx_state =
        std::cell::RefCell::new(crate::exec::op_ccv::CCVTxState::new(tx.output.len()));

    // Step 4: Execute each input script with its witness
    for ((input_idx, script), (witness_index, witness_stack)) in inputs.iter().zip(witness_stacks) {
        if *input_idx != witness_index {
            return Err(Error::WitnessIndexesMismatch {
                expected: witness_index,
                found: *input_idx,
            });
        }

        let mut exec = Exec::new_with_ccv(
            &mut sighashcache,
            prevouts,
            *input_idx,
            script,
            witness_stack,
            &ccv_tx_state,
        )?;

        loop {
            match exec.exec_next() {
                Ok(_) => continue,
                Err(exec::ExecError::NoMoreInstructions { success: true }) => break,
                Err(exec::ExecError::NoMoreInstructions { success: false }) => {
                    return Err(Error::ScriptVerificationFailed {
                        input: *input_idx,
                        final_stack: exec.stack,
                    });
                }
                Err(err) => {
                    //  TODO: log stack

                    // Return execution error
                    return Err(Error::Exec(err));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::{
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
        hashes::Hash,
        key::{Keypair, Secp256k1},
        opcodes::all::{OP_PUSHNUM_6, OP_PUSHNUM_7, OP_PUSHNUM_8, OP_PUSHNUM_16},
        secp256k1::{self, All, Message},
        sighash::{Prevouts, SighashCache},
    };

    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    use crate::{EncodeSakeScript, Error, SakeWitnessCarrier, validate, validate_and_sign};

    pub fn dummy_tx() -> (Transaction, Vec<TxOut>) {
        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output:
                        "1111111111111111111111111111111111111111111111111111111111111111:1"
                            .parse()
                            .unwrap(),
                    script_sig: vec![0x23].into(),
                    sequence: Sequence::from_consensus(1),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output:
                        "2222222222222222222222222222222222222222222222222222222222222222:2"
                            .parse()
                            .unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(3),
                    witness: {
                        // p2wsh annex-like stack element
                        let mut buf = Witness::new();
                        buf.push(vec![0x13]);
                        buf.push(vec![0x14]);
                        buf.push(vec![0x50, 0x42]); // annex
                        buf
                    },
                },
                TxIn {
                    previous_output:
                        "3333333333333333333333333333333333333333333333333333333333333333:3"
                            .parse()
                            .unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(2),
                    witness: {
                        let mut buf = Witness::new();
                        buf.push(vec![0x12]);
                        buf
                    },
                },
                TxIn {
                    previous_output:
                        "4444444444444444444444444444444444444444444444444444444444444444:4"
                            .parse()
                            .unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(3),
                    witness: {
                        let mut buf = Witness::new();
                        buf.push(vec![0x13]);
                        buf.push(vec![0x14]);
                        buf.push(vec![0x50, 0x42]); // annex
                        buf
                    },
                },
            ],
            output: vec![
                TxOut {
                    script_pubkey: vec![OP_PUSHNUM_6.to_u8()].into(),
                    value: Amount::from_sat(350),
                },
                TxOut {
                    script_pubkey: vec![OP_PUSHNUM_7.to_u8()].into(),
                    value: Amount::from_sat(351),
                },
                TxOut {
                    script_pubkey: vec![OP_PUSHNUM_8.to_u8()].into(),
                    value: Amount::from_sat(353),
                },
            ],
        };
        let prevouts = vec![
            TxOut {
                script_pubkey: vec![OP_PUSHNUM_16.to_u8()].into(),
                value: Amount::from_sat(360),
            },
            TxOut {
                script_pubkey: vec![
                    // p2wsh
                    0x00, 0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
                .into(),
                value: Amount::from_sat(361),
            },
            TxOut {
                script_pubkey: vec![
                    // p2tr
                    0x51, 0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
                .into(),
                value: Amount::from_sat(362),
            },
            TxOut {
                script_pubkey: vec![
                    // p2tr
                    0x51, 0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
                .into(),
                value: Amount::from_sat(363),
            },
        ];

        (dummy_tx, prevouts)
    }

    pub fn dummy_tx_with_witness_carrier(witness: Vec<Vec<u8>>) -> (Transaction, Vec<TxOut>) {
        let (mut dummy_tx, prevouts) = dummy_tx();

        dummy_tx
            .output
            .push(TxOut::sake_witness_carrier(&[(0, witness)]));

        (dummy_tx, prevouts)
    }

    pub fn validate_single_script(
        emulated_script: ScriptBuf,
        witness: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let (dummy_tx, prevouts) = dummy_tx_with_witness_carrier(witness);

        let script = script! {
            {
                emulated_script.encode_sake_script(
                    &[
                        XOnlyPublicKey::from_str("18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166").unwrap()
                    ],
                    0
                ).unwrap()
            }
        };

        validate(&dummy_tx, &prevouts, &[(0, script)])
    }

    /// Returns (pk, msg, sig) bytes
    pub fn mock_signed_message(secp: &Secp256k1<All>) -> (XOnlyPublicKey, [u8; 32], [u8; 64]) {
        // Generate a random keypair for the test
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(secp, &mut rng);
        let pk = keypair.x_only_public_key().0;

        // BIP 348 requires a 32-byte message for the current BIP 340 implementation
        let msg_bytes = [0x42u8; 32];
        let msg = secp256k1::Message::from_digest_slice(&msg_bytes).unwrap();
        let sig = secp.sign_schnorr(&msg, &keypair);

        (pk, msg_bytes, sig.serialize())
    }

    #[test]
    fn test_validate_and_sign_success() {
        // Sign the first and last inputs
        let scripts = vec![
            // Input 0: Script that passes if witness is 1
            (0, script! { OP_IF { 1 } OP_ELSE { 0 } OP_ENDIF }),
            // Input 2: Script that passes if witness is 0
            (2, script! { OP_IF { 0 } OP_ELSE { 1 } OP_ENDIF }),
        ];

        // Witness stacks encoded in witness carrier
        let witness_carrier = TxOut::sake_witness_carrier(&[
            (0, vec![vec![1]]), // Ipnut 0 witness stack: [ OP_1 ]
            (2, vec![vec![]]),  // Ipnut 2 witness stack: [ OP_0 ]
        ]);

        // MUST have at least 2 inputs because we are signing input 0 and 1
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default(), Default::default(), Default::default()],
            output: vec![witness_carrier],
        };

        let secp = Secp256k1::new();

        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let public_key = keypair.x_only_public_key().0;

        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
            },
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
            },
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
            },
        ];

        let sigs = validate_and_sign(&keypair, &tx, &prevouts, &scripts)
            .expect("Validation and signing failed");

        assert_eq!(sigs.len(), 2);

        // Manually verify the signatures against the sighashes to ensure they are valid BIP-340 sigs
        let mut cache = SighashCache::new(&tx);
        let prevouts_all = Prevouts::All(&prevouts);

        for (i, (input_idx, _)) in scripts.iter().enumerate() {
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    *input_idx,
                    &prevouts_all,
                    bitcoin::TapSighashType::All,
                )
                .unwrap();

            let msg = Message::from_digest(sighash.to_byte_array());

            // Verify using secp
            secp.verify_schnorr(&sigs[i], &msg, &public_key)
                .expect("Signature verification failed");
        }
    }

    #[test]
    fn test_validate_large_script() {
        // Create a large SAKE script programmatically (100KB)
        // by repeating OP_16 OP_DROP pairs many times, then ending with 1
        // This tests that the validation pipeline handles large encoded scripts correctly
        let mut script_bytes = Vec::new();

        // Each iteration adds: OP_16 (1 byte) + OP_DROP (1 byte) = 2 bytes
        // We want ~100KB, so ~50,000 iterations
        for _ in 0..50000 {
            script_bytes.push(0x60u8); // OP_16 pushes 16 to the stack
            script_bytes.push(0x75u8); // OP_DROP removes the top stack item
        }
        script_bytes.push(0x51u8); // OP_1 pushes 1 to the stack (final result)

        let large_script = ScriptBuf::from_bytes(script_bytes);

        // Verify the script is large enough (>50KB)
        assert!(
            large_script.as_bytes().len() > 50000,
            "Script should be >50KB, got {} bytes",
            large_script.as_bytes().len()
        );

        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let public_key = keypair.x_only_public_key().0;

        // Encode the large script
        let encoded_script = large_script
            .encode_sake_script(&[public_key], 1)
            .expect("Should encode large script successfully");

        // Create a transaction with witness carrier for the large script
        // No witness data needed since the script is self-contained
        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![])]);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![witness_carrier],
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
        }];

        // Validate the transaction with the large script
        // This tests that the validation pipeline handles large encoded scripts correctly
        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "Transaction with large script should validate successfully: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_large_witness_carrier() {
        // Test validation with large witness data in the carrier
        // Create witness data larger than 520 bytes to test chunking
        let large_witness_element = vec![0x42u8; 600]; // 600 bytes > 520 byte push limit
        let large_witness_stack = vec![large_witness_element.clone()];

        // Script that checks the witness data size
        let script = script! {
            // Get size of top element, compare to 600, then drop the element
            OP_SIZE
            600 OP_EQUALVERIFY
            OP_DROP
            1
        };

        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let public_key = keypair.x_only_public_key().0;

        // Encode the script
        let encoded_script = script
            .encode_sake_script(&[public_key], 1)
            .expect("Should encode script successfully");

        // Create witness carrier with large witness data (>520 bytes)
        let witness_carrier = TxOut::sake_witness_carrier(&[(0, large_witness_stack.clone())]);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![witness_carrier],
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
        }];

        // Validate the transaction with large witness carrier
        let result = validate(&tx, &prevouts, &[(0, encoded_script)]);
        assert!(
            result.is_ok(),
            "Transaction with large witness carrier should validate successfully: {:?}",
            result.err()
        );

        // Also test with multiple large witness elements
        let multiple_large_elements = vec![vec![0xAAu8; 400], vec![0xBBu8; 400], vec![0xCCu8; 400]];

        // Script for multiple elements
        // Witness stack: [element1, element2, element3] (element3 on top)
        let multi_script = script! {
            // Check third element size (400) - on top
            OP_SIZE
            400 OP_EQUALVERIFY
            OP_DROP
            // Check second element size (400)
            OP_SIZE
            400 OP_EQUALVERIFY
            OP_DROP
            // Check first element size (400)
            OP_SIZE
            400 OP_EQUALVERIFY
            OP_DROP
            1
        };

        let encoded_multi_script = multi_script
            .encode_sake_script(&[public_key], 1)
            .expect("Should encode multi script successfully");

        let multi_witness_carrier = TxOut::sake_witness_carrier(&[(0, multiple_large_elements)]);

        let multi_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![multi_witness_carrier],
        };

        let result_multi = validate(&multi_tx, &prevouts, &[(0, encoded_multi_script)]);
        assert!(
            result_multi.is_ok(),
            "Transaction with multiple large witness elements should validate successfully: {:?}",
            result_multi.err()
        );
    }

    #[test]
    fn test_validate_with_no_sake_scripts() {
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let public_key = keypair.x_only_public_key().0;

        let non_sake_script = script! { OP_DROP OP_FALSE };

        let witness_carrier = TxOut::sake_witness_carrier(&[(0, vec![vec![]])]);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![witness_carrier],
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
        }];

        let result = validate(&tx, &prevouts, &[(0, non_sake_script)]);
        assert!(
            result.is_ok(),
            "Transaction without SAKE scripts should validate successfully: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_with_no_sake_scripts_nor_witness_carrier() {
        let secp = Secp256k1::new();
        let secret_key = [0x42; 32];
        let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
        let public_key = keypair.x_only_public_key().0;

        let non_sake_script = script! { OP_FALSE };

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };

        let prevouts = vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
        }];

        let result = validate(&tx, &prevouts, &[(0, non_sake_script)]);
        assert!(
            result.is_ok(),
            "Transaction without SAKE scripts should validate successfully: {:?}",
            result.err()
        );
    }
}
