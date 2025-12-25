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
mod stack;
mod witness_carrier;

use exec::Exec;

pub use error::Error;
pub use witness_carrier::SakeWitnessCarrier;

pub use exec::op_csfsv::{OP_CHECKSIGFROMSTACKVERIFY, OP_CSFSV};
pub use exec::op_ctv::*;

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
    validate_inner(&mut tx.clone(), prevouts, inputs, true)
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

    validate_inner(&mut emulated_tx, prevouts, inputs, true)?;

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

/// Validates scripts in a transaction with _NO_ support for SAKE scripts.
///
/// - `tx`: The transaction (used to calculate the sighash) and the last output contains the script witnesses as an OP_RETURN
/// - `prevouts`: All the previous [TxOut]s for all the inputs (used to calculate the sighash).
/// - `scripts` : Tuples of (`input index`, `ScriptBuf`) for the inputs to evaluate.
///     - `input_index`: used in sighash calculation.
///     - `ScriptBuf`: locking script for this input, evaluated with the respective script witness defcoded from the last [TxOut] (`OP_RETURN`) in the `tx`.
pub fn validate_no_sake(
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[(usize, ScriptBuf)],
) -> Result<(), Error> {
    validate_inner(&mut tx.clone(), prevouts, inputs, false)
}

fn validate_inner<'a>(
    tx: &mut Transaction,
    prevouts: &'a [TxOut],
    inputs: &'a [(usize, ScriptBuf)],

    supports_sake: bool,
) -> Result<(), Error> {
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }

    let last_output = tx.output.pop();

    // Step 1: Extract witness stacks from the last output if it's OP_RETURN
    let witness_stacks = if let Some(last_output) = last_output {
        last_output
            .parse_witness_stacks()
            .map_err(Error::InvalidWitnessCarriers)?
    } else {
        vec![]
    };

    // Step 2: Validate count
    if witness_stacks.len() != inputs.len() {
        return Err(Error::WitnessCountMismatch {
            expected: inputs.len(),
            found: witness_stacks.len(),
        });
    }

    // SighashCache from the transaction without the witness stack.
    //
    // This is because the witness stack may include a TXHASH that
    // can't be created from the transaction with the witness carrier,
    // since the circular dependency
    let mut sighashcache = SighashCache::new(tx.clone());

    // Step 3: Execute each input script with its witness
    for ((input_idx, script), (witness_index, witness_stack)) in inputs.iter().zip(witness_stacks) {
        if *input_idx != witness_index {
            return Err(Error::WitnessIndexesMismatch {
                expected: witness_index,
                found: *input_idx,
            });
        }

        let mut exec = Exec::new(
            &mut sighashcache,
            prevouts,
            *input_idx,
            script,
            witness_stack.clone(),
            supports_sake,
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

    use bitcoin::{
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
        hashes::Hash,
        key::{Keypair, Secp256k1},
        opcodes::all::{OP_PUSHNUM_6, OP_PUSHNUM_7, OP_PUSHNUM_8, OP_PUSHNUM_16},
        secp256k1::{self, All, Message},
        sighash::{Prevouts, SighashCache},
    };

    use bitcoin_script::{Script, script};

    use crate::{
        Error, SakeWitnessCarrier, calculate_txhash, validate, validate_and_sign, validate_no_sake,
    };

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
                value: Amount::from_sat(361),
            },
            TxOut {
                script_pubkey: vec![
                    // p2tr
                    0x51, 0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
                .into(),
                value: Amount::from_sat(362),
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

    pub fn validate_single_script(script: ScriptBuf, witness: Vec<Vec<u8>>) -> Result<(), Error> {
        let (dummy_tx, prevouts) = dummy_tx_with_witness_carrier(witness);

        validate(&dummy_tx, &prevouts, &[(0, script)])
    }

    pub fn validate_single_script_no_sake_support(
        script: ScriptBuf,
        witness: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let (dummy_tx, prevouts) = dummy_tx_with_witness_carrier(witness);

        validate_no_sake(&dummy_tx, &prevouts, &[(0, script)])
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

    fn sake_script(pk: XOnlyPublicKey) -> Script {
        // Tx without the witness carrier
        let (tx, prevouts) = dummy_tx();

        script! {
            // Test OP_CAT
            { b"world".to_vec() }
            OP_CAT
            { b"hello world".to_vec() }
            OP_EQUALVERIFY

            // Test OP_CHECKTXHASHVERIFY
            {
                calculate_txhash(&[], &tx, &prevouts, 0, None)
                .unwrap()
                .to_byte_array()
                .to_vec()
            }
            OP_CTV
            OP_DROP

            // Test OP_CHECKSIGFROMSTACKVERIFY
            { pk }
            OP_CHECKSIGFROMSTACKVERIFY
            OP_2DROP
            OP_DROP

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

    #[test]
    fn test_validate_and_sign_success() {
        // Sign the first and last inputs
        let scripts = vec![
            // Input 0: Script that passes if witness is 1
            (0, script! { OP_IF { 1 } OP_ELSE { 0 } OP_ENDIF }.compile()),
            // Input 2: Script that passes if witness is 0
            (2, script! { OP_IF { 0 } OP_ELSE { 1 } OP_ENDIF }.compile()),
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
}
