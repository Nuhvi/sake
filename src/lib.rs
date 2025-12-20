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

pub use exec::OP_CHECKSIGFROMSTACK;

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
    let last_output = tx.output.last();
    let mut sighashcache = SighashCache::new(tx);

    validate_with_sighashcache(&mut sighashcache, last_output, prevouts, inputs, true)
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
    let last_output = tx.output.last();
    let mut sighashcache = SighashCache::new(tx);

    validate_with_sighashcache(&mut sighashcache, last_output, prevouts, inputs, true)?;

    let mut signatures = Vec::with_capacity(inputs.len());

    // Taproot sighashes require knowledge of all prevouts being spent
    let prevouts_all = Prevouts::All(prevouts);

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
    let last_output = tx.output.last();
    let mut sighashcache = SighashCache::new(tx);

    validate_with_sighashcache(&mut sighashcache, last_output, prevouts, inputs, false)
}

fn validate_with_sighashcache<'a>(
    sighashcache: &mut SighashCache<&'a Transaction>,
    last_output: Option<&TxOut>,
    prevouts: &'a [TxOut],
    inputs: &'a [(usize, ScriptBuf)],

    supports_sake: bool,
) -> Result<(), Error> {
    if inputs.is_empty() {
        return Ok(());
    }

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

    // Step 3: Execute each input script with its witness
    for ((input_idx, script), (witness_index, witness_stack)) in inputs.iter().zip(witness_stacks) {
        if *input_idx != witness_index {
            return Err(Error::WitnessIndexesMismatch {
                expected: witness_index,
                found: *input_idx,
            });
        }

        let mut exec = Exec::new(
            sighashcache,
            prevouts,
            *input_idx,
            script,
            witness_stack.clone(),
            supports_sake,
        )?;

        loop {
            match exec.exec_next() {
                Ok(_) => continue,
                Err(exec::ExecError::Done(true)) => break,
                Err(exec::ExecError::Done(false)) => {
                    return Err(Error::ScriptVerificationFailed { input: *input_idx });
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
        ScriptBuf, Transaction, TxOut,
        key::Secp256k1,
        secp256k1::{self, All},
    };

    use crate::{Error, SakeWitnessCarrier, validate, validate_no_sake};

    pub fn validate_single_script(script: ScriptBuf, witness: Vec<Vec<u8>>) -> Result<(), Error> {
        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut::sake_witness_carrier(&[(0, witness)])],
        };
        let prevouts = vec![];

        validate(&dummy_tx, &prevouts, &[(0, script)])
    }

    pub fn validate_single_script_no_sake_support(
        script: ScriptBuf,
        witness: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut::sake_witness_carrier(&[(0, witness)])],
        };
        let prevouts = vec![];

        validate_no_sake(&dummy_tx, &prevouts, &[(0, script)])
    }

    /// Returns (pk, msg, sig) bytes
    pub fn mock_signed_message(secp: &Secp256k1<All>) -> ([u8; 32], [u8; 32], [u8; 64]) {
        // Generate a random keypair for the test
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(secp, &mut rng);
        let pk = keypair.x_only_public_key().0;

        // BIP 348 requires a 32-byte message for the current BIP 340 implementation
        let msg_bytes = [0x42u8; 32];
        let msg = secp256k1::Message::from_digest_slice(&msg_bytes).unwrap();
        let sig = secp.sign_schnorr(&msg, &keypair);

        (pk.serialize(), msg_bytes, sig.serialize())
    }
}
