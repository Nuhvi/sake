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

use crate::witness_carrier::TryFromSakeWitnessCarrier;

pub use crate::exec::Error;
pub use exec::Exec;
pub use witness_carrier::SakeWitnessCarrier;

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

    validate_with_sighashcache(&mut sighashcache, last_output, prevouts, inputs)
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

    validate_with_sighashcache(&mut sighashcache, last_output, prevouts, inputs)?;

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

fn validate_with_sighashcache<'a>(
    sighashcache: &mut SighashCache<&'a Transaction>,
    last_output: Option<&TxOut>,
    prevouts: &'a [TxOut],
    inputs: &'a [(usize, ScriptBuf)],
) -> Result<(), Error> {
    if inputs.is_empty() {
        return Ok(());
    }

    // Step 1: Extract witness stacks from the last output if it's OP_RETURN
    let witness_stacks = if let Some(last_output) = last_output {
        last_output
            .script_pubkey
            .as_script()
            .try_into_witness_stacks()
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
    for ((input_idx, script), witness_stack) in inputs.iter().zip(witness_stacks) {
        let mut exec = Exec::new(
            sighashcache,
            prevouts,
            *input_idx,
            script,
            witness_stack.clone(),
        )?;

        loop {
            match exec.exec_next() {
                Ok(_) => continue,
                Err(exec_result) => {
                    if let Some(err) = &exec_result.error {
                        //  TODO: log stack

                        // Return execution error
                        return Err(Error::Exec(err.clone()));
                    } else if !exec_result.success {
                        return Err(Error::ScriptVerificationFailed(inputs.first().unwrap().0));
                    }

                    break; // Script finished successfully
                }
            }
        }
    }

    Ok(())
}
