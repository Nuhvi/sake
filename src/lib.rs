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

use std::collections::HashMap;

use bitcoin::{
    Script, ScriptBuf, TapSighashType, Transaction, TxOut, Witness, XOnlyPublicKey,
    hashes::Hash,
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message, schnorr},
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash},
};

mod error;
mod exec;
mod script_encoding;
mod stack;
mod witness_carrier;

use exec::Exec;

pub use error::{Error, ExecError};
pub use script_encoding::{
    EncodeSakeScript, MAX_ORACLES, ScriptDecodingError, ScriptEncodingError,
};
pub use stack::Stack;
pub use witness_carrier::{SakeWitnessCarrier, WitnessCarrierError};

pub use exec::op_amount::{
    OP_AMOUNT, OP_AMOUNT_CURRENT_INPUT_SELECTOR, OpAmountError, op_amount_input_selector,
    op_amount_output_selector,
};
pub use exec::op_ccv::{BIP341_NUMS_KEY, CCVMode, OP_CCV, OP_CHECKCONTRACTVERIFY};
pub use exec::op_csfs::{OP_CHECKSIGFROMSTACK, OP_CSFS};
pub use exec::op_th::{OP_TEMPLATEHASH, OP_TH};

/// One input to validate.
///
/// Only inputs whose `script` contains a SAKE encoding are validated and
/// signed. Other inputs are ignored: an oracle cannot attest to arbitrary
/// native tapscript execution without full chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SakeInput {
    /// Index of this input in the transaction.
    pub input_index: usize,
    /// The full tapscript for this input.
    pub script: ScriptBuf,
    /// Control block proving `script` against the spent output. When present,
    /// [`validate`] checks the taproot commitment and derives the current
    /// input's internal key and taptree for `OP_CHECKCONTRACTVERIFY`'s `-1`
    /// values.
    ///
    /// Oracles should require this for production signing. Without it the
    /// library cannot prove that `script` is committed by the prevout, even
    /// though the returned signature is still bound to the leaf hash.
    pub control_block: Option<ControlBlock>,
    /// Test-only override for the current input's internal key and taptree
    /// Merkle root, used by `OP_CHECKCONTRACTVERIFY`'s `-1` values. This field
    /// is not part of the public API; production derives the spend info from
    /// `control_block`.
    #[cfg(test)]
    pub(crate) spend_info: Option<(XOnlyPublicKey, TapNodeHash)>,
}

impl SakeInput {
    /// Builds an input from an explicit script.
    pub fn new(input_index: usize, script: ScriptBuf) -> Self {
        Self::new_inner(input_index, script, None)
    }

    #[cfg(not(test))]
    fn new_inner(
        input_index: usize,
        script: ScriptBuf,
        control_block: Option<ControlBlock>,
    ) -> Self {
        Self {
            input_index,
            script,
            control_block,
        }
    }

    #[cfg(test)]
    fn new_inner(
        input_index: usize,
        script: ScriptBuf,
        control_block: Option<ControlBlock>,
    ) -> Self {
        Self {
            input_index,
            script,
            control_block,
            spend_info: None,
        }
    }

    /// Builds an input from a full taproot witness: `[stack..., script, control_block]`.
    ///
    /// The initial stack is not needed for SAKE inputs (the emulation stack is
    /// read from the witness carrier). An annex (last element starting with
    /// `0x50`) is rejected.
    pub fn from_witness(input_index: usize, witness: &Witness) -> Result<Self, Error> {
        let elements: Vec<&[u8]> = witness.iter().collect();
        if elements.len() >= 2
            && elements
                .last()
                .and_then(|element| element.first())
                .is_some_and(|byte| *byte == 0x50)
        {
            return Err(Error::AnnexNotSupported { input: input_index });
        }
        let script_index = elements
            .len()
            .checked_sub(2)
            .ok_or(Error::InvalidWitness { input: input_index })?;
        let script = elements
            .get(script_index)
            .ok_or(Error::InvalidWitness { input: input_index })?;
        let control_block = elements
            .get(script_index + 1)
            .ok_or(Error::InvalidWitness { input: input_index })?;
        let control_block = ControlBlock::decode(control_block).map_err(Error::ControlBlock)?;
        Ok(Self::new_inner(
            input_index,
            ScriptBuf::from_bytes(script.to_vec()),
            Some(control_block),
        ))
    }
}

/// Validates the SAKE inputs of a transaction.
///
/// Inputs whose script does not contain a SAKE encoding are ignored. If the
/// list is non-empty but no input has a SAKE encoding, validation succeeds
/// without doing anything. An empty `inputs` slice returns [`Error::NoInputs`].
///
/// - `tx`: The transaction (used to calculate the sighash) and, when it has
///   SAKE inputs, the last output is the witness carrier (`OP_RETURN`).
/// - `prevouts`: All the previous [TxOut]s for all the inputs.
/// - `inputs`: The inputs to evaluate.
pub fn validate(tx: &Transaction, prevouts: &[TxOut], inputs: &[SakeInput]) -> Result<(), Error> {
    let secp = Secp256k1::new();
    validate_inner(&secp, None, tx, prevouts, inputs).map(|_| ())
}

/// Validates SAKE inputs and returns one script-spend signature per SAKE input,
/// together with the input index.
///
/// Signatures use `SIGHASH_DEFAULT` over the full tapscript leaf. Inputs whose
/// script does not contain a SAKE encoding are ignored and produce no
/// signature.
///
/// - `keypair`: Oracle's keypair.
/// - `tx`, `prevouts`, `inputs`: See [`validate`].
pub fn validate_and_sign(
    keypair: &Keypair,
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[SakeInput],
) -> Result<Vec<(usize, schnorr::Signature)>, Error> {
    let secp = Secp256k1::new();
    validate_and_sign_with_secp(&secp, keypair, tx, prevouts, inputs)
}

/// Like [`validate_and_sign`], with a caller-provided secp256k1 context.
pub fn validate_and_sign_with_secp(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[SakeInput],
) -> Result<Vec<(usize, schnorr::Signature)>, Error> {
    validate_inner(secp, Some(keypair), tx, prevouts, inputs)
}

struct ParsedInput {
    index: usize,
    script: ScriptBuf,
    spend_info: Option<(XOnlyPublicKey, TapNodeHash)>,
    emulated: ScriptBuf,
    sake_stack: Option<Vec<Vec<u8>>>,
}

fn validate_inner(
    secp: &Secp256k1<All>,
    keypair: Option<&Keypair>,
    tx: &Transaction,
    prevouts: &[TxOut],
    inputs: &[SakeInput],
) -> Result<Vec<(usize, schnorr::Signature)>, Error> {
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    if prevouts.len() != tx.input.len() {
        return Err(Error::PrevoutsCountMismatch {
            expected: tx.input.len(),
            found: prevouts.len(),
        });
    }

    let mut parsed = Vec::with_capacity(inputs.len());
    for input in inputs {
        if input.input_index >= tx.input.len() {
            return Err(Error::InvalidInputIndex {
                input: input.input_index,
                count: tx.input.len(),
            });
        }
        let emulated = script_encoding::extract_encoded_script(&input.script)
            .map_err(Error::InvalidScriptEncoding)?;
        let Some(emulated) = emulated else {
            // Not a SAKE input: the oracle does not validate native scripts.
            continue;
        };
        let control_block = input.control_block.as_ref();
        if let Some(control_block) = control_block {
            let prevout = prevouts
                .get(input.input_index)
                .ok_or(Error::InvalidInputIndex {
                    input: input.input_index,
                    count: tx.input.len(),
                })?;
            verify_control_block(
                secp,
                prevout,
                &input.script,
                control_block,
                input.input_index,
            )?;
        }
        let derived_spend_info =
            control_block.map(|control_block| current_spend_info(&input.script, control_block));
        #[cfg(test)]
        let override_spend_info = input.spend_info;
        #[cfg(not(test))]
        let override_spend_info: Option<(XOnlyPublicKey, TapNodeHash)> = None;
        parsed.push(ParsedInput {
            index: input.input_index,
            script: input.script.clone(),
            spend_info: override_spend_info.or(derived_spend_info),
            emulated,
            sake_stack: None,
        });
    }

    if parsed.is_empty() {
        return Ok(Vec::new());
    }

    // Remove the witness carrier from the transaction used by the emulator.
    let mut stripped_tx = tx.clone();
    let mut carrier: HashMap<usize, Vec<Vec<u8>>> = HashMap::new();
    let carrier_output = stripped_tx
        .output
        .pop()
        .ok_or(Error::InvalidWitnessCarriers(
            witness_carrier::WitnessCarrierError::NotOpReturn,
        ))?;
    for (input_index, stack) in carrier_output
        .parse_witness_stacks()
        .map_err(Error::InvalidWitnessCarriers)?
    {
        if carrier.insert(input_index, stack).is_some() {
            return Err(Error::DuplicateSakeWitness { input: input_index });
        }
    }
    for parsed_input in parsed.iter_mut() {
        let stack = carrier
            .remove(&parsed_input.index)
            .ok_or(Error::MissingSakeWitness {
                input: parsed_input.index,
            })?;
        parsed_input.sake_stack = Some(stack);
    }
    if let Some((input_index, _)) = carrier.into_iter().next() {
        return Err(Error::UnexpectedSakeWitness { input: input_index });
    }

    let ccv_tx_state =
        std::cell::RefCell::new(exec::op_ccv::CCVTxState::new(stripped_tx.output.len()));
    let mut full_sighashcache = SighashCache::new(tx.clone());
    let mut stripped_sighashcache = SighashCache::new(stripped_tx.clone());

    let mut signatures = Vec::with_capacity(parsed.len());
    for parsed_input in &parsed {
        let signature = if let Some(keypair) = keypair {
            let leaf_hash = TapLeafHash::from_script(&parsed_input.script, LeafVersion::TapScript);
            let sighash = full_sighashcache
                .taproot_script_spend_signature_hash(
                    parsed_input.index,
                    &Prevouts::All(prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .map_err(Error::SigningError)?;
            let msg = Message::from_digest(sighash.to_byte_array());
            Some(secp.sign_schnorr(&msg, keypair))
        } else {
            None
        };

        let (internal_key, taptree) = match parsed_input.spend_info {
            Some((internal_key, taptree)) => (Some(internal_key), Some(taptree)),
            None => (None, None),
        };
        let stack = parsed_input
            .sake_stack
            .as_ref()
            .ok_or(Error::MissingSakeWitness {
                input: parsed_input.index,
            })?
            .clone();
        let mut exec = Exec::new_with_ccv(
            &mut stripped_sighashcache,
            prevouts,
            parsed_input.index,
            &parsed_input.emulated,
            stack,
            &ccv_tx_state,
            internal_key,
            taptree,
        )?;
        run_exec(&mut exec, parsed_input.index)?;

        if let Some(signature) = signature {
            signatures.push((parsed_input.index, signature));
        }
    }

    Ok(signatures)
}

fn run_exec(exec: &mut Exec, input: usize) -> Result<(), Error> {
    loop {
        match exec.exec_next() {
            Ok(()) => {}
            Err(exec::ExecError::NoMoreInstructions { success: true }) => return Ok(()),
            Err(exec::ExecError::NoMoreInstructions { success: false }) => {
                return Err(Error::ScriptVerificationFailed {
                    input,
                    final_stack: exec.stack.clone(),
                });
            }
            Err(err) => return Err(Error::Exec(err)),
        }
    }
}

fn verify_control_block(
    secp: &Secp256k1<All>,
    prevout: &TxOut,
    script: &Script,
    control_block: &ControlBlock,
    input: usize,
) -> Result<(), Error> {
    if control_block.leaf_version != LeafVersion::TapScript {
        return Err(Error::UnsupportedLeafVersion { input });
    }
    if !prevout.script_pubkey.is_p2tr() {
        return Err(Error::NotP2trPrevout { input });
    }
    let output_key_bytes = prevout
        .script_pubkey
        .as_bytes()
        .get(2..34)
        .ok_or(Error::NotP2trPrevout { input })?;
    let output_key = XOnlyPublicKey::from_slice(output_key_bytes)
        .map_err(|_| Error::NotP2trPrevout { input })?;
    if !control_block.verify_taproot_commitment(secp, output_key, script) {
        return Err(Error::ControlBlockMismatch { input });
    }
    Ok(())
}

fn current_spend_info(
    script: &Script,
    control_block: &ControlBlock,
) -> (XOnlyPublicKey, TapNodeHash) {
    let mut root = TapNodeHash::from_script(script, LeafVersion::TapScript);
    for node in control_block.merkle_branch.as_slice() {
        root = TapNodeHash::from_node_hashes(root, *node);
    }
    (control_block.internal_key, root)
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::{
        Amount, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
        Witness, XOnlyPublicKey,
        key::{Keypair, Secp256k1},
        opcodes::all::{OP_PUSHNUM_6, OP_PUSHNUM_7, OP_PUSHNUM_8, OP_PUSHNUM_16},
        secp256k1::{self, All},
        sighash::{Prevouts, SighashCache},
        taproot::{LeafVersion, TaprootBuilder},
    };

    use bitcoin_script::{define_pushable, script};

    define_pushable!();

    use crate::{
        EncodeSakeScript, Error, ExecError, OP_CHECKCONTRACTVERIFY, SakeInput, SakeWitnessCarrier,
        validate, validate_and_sign,
    };

    pub fn dummy_tx() -> (Transaction, Vec<TxOut>) {
        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
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
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output:
                        "3333333333333333333333333333333333333333333333333333333333333333:3"
                            .parse()
                            .unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(2),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output:
                        "4444444444444444444444444444444444444444444444444444444444444444:4"
                            .parse()
                            .unwrap(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(3),
                    witness: Witness::new(),
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
        let (dummy_tx, prevouts) = dummy_tx_with_witness_carrier(witness.clone());

        let script = script! {
            {
                emulated_script.encode_sake_script(
                    &[
                        XOnlyPublicKey::from_str("18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166").unwrap()
                    ],
                    1
                ).unwrap()
            }
        };

        validate(&dummy_tx, &prevouts, &[SakeInput::new(0, script)])
    }

    /// Returns (pk, msg, sig) bytes
    pub fn mock_signed_message(secp: &Secp256k1<All>) -> (XOnlyPublicKey, [u8; 32], [u8; 64]) {
        // Generate a random keypair for the test
        let mut rng = secp256k1::rand::thread_rng();
        let keypair = secp256k1::Keypair::new(secp, &mut rng);
        let pk = keypair.x_only_public_key().0;

        // BIP 340 requires a 32-byte message for the current secp256k1 binding
        let msg_bytes = [0x42u8; 32];
        let msg = secp256k1::Message::from_digest_slice(&msg_bytes).unwrap();
        let sig = secp.sign_schnorr(&msg, &keypair);

        (pk, msg_bytes, sig.serialize())
    }

    fn oracle_keypair() -> (Secp256k1<All>, Keypair, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[0x42; 32]).unwrap();
        let pk = keypair.x_only_public_key().0;
        (secp, keypair, pk)
    }

    fn single_input_tx(script: ScriptBuf) -> (Transaction, Vec<TxOut>) {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };
        let prevouts = vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: script,
        }];
        (tx, prevouts)
    }

    #[test]
    fn test_validate_and_sign_uses_script_spend_sighash() {
        let (secp, keypair, pk) = oracle_keypair();
        let (mut tx, prevouts) = single_input_tx(ScriptBuf::new());
        tx.output.push(TxOut::sake_witness_carrier(&[(0, vec![])]));

        let native = script! { OP_1 }.encode_sake_script(&[pk], 1).unwrap();
        let signatures = validate_and_sign(
            &keypair,
            &tx,
            &prevouts,
            &[SakeInput::new(0, native.clone())],
        )
        .unwrap();

        let mut cache = SighashCache::new(&tx);
        let leaf_hash = TapLeafHash::from_script(&native, LeafVersion::TapScript);
        let script_sighash = cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let key_sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();

        assert_eq!(signatures[0].0, 0);
        secp.verify_schnorr(&signatures[0].1, &script_sighash.into(), &pk)
            .expect("signature must verify for the script spend sighash");
        assert!(
            secp.verify_schnorr(&signatures[0].1, &key_sighash.into(), &pk)
                .is_err(),
            "signature must not be a key spend signature"
        );
        assert_eq!(signatures[0].1.as_ref().len(), 64);
    }

    #[test]
    fn test_validate_and_sign_rejects_invalid_sake_script() {
        let (_secp, keypair, pk) = oracle_keypair();
        let (mut tx, prevouts) = single_input_tx(ScriptBuf::new());
        tx.output.push(TxOut::sake_witness_carrier(&[(0, vec![])]));

        let native = script! { OP_0 }.encode_sake_script(&[pk], 1).unwrap();
        let result = validate_and_sign(&keypair, &tx, &prevouts, &[SakeInput::new(0, native)]);
        assert!(matches!(
            result,
            Err(Error::ScriptVerificationFailed { .. })
        ));
    }

    #[test]
    fn test_validate_large_script_uses_chunked_encoding() {
        // 100KB of OP_16 OP_DROP pairs, ending with OP_1.
        let mut script_bytes = Vec::new();
        for _ in 0..50000 {
            script_bytes.push(0x60u8);
            script_bytes.push(0x75u8);
        }
        script_bytes.push(0x51u8);
        let large_script = ScriptBuf::from_bytes(script_bytes);

        let (_secp, _keypair, pk) = oracle_keypair();
        let encoded = large_script
            .clone()
            .encode_sake_script(&[pk], 1)
            .expect("chunked encoding should succeed");

        // Every push in the native script must respect the 520 byte limit.
        for instruction in encoded.instructions() {
            if let bitcoin::script::Instruction::PushBytes(bytes) = instruction.unwrap() {
                assert!(bytes.len() <= 520, "push of {} bytes", bytes.len());
            }
        }

        let decoded = crate::script_encoding::extract_encoded_script(&encoded)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, large_script);

        let (mut tx, prevouts) = single_input_tx(ScriptBuf::new());
        tx.output.push(TxOut::sake_witness_carrier(&[(0, vec![])]));
        assert!(validate(&tx, &prevouts, &[SakeInput::new(0, encoded)]).is_ok());
    }

    #[test]
    fn test_validate_rejects_witness_element_over_520() {
        let (_secp, _keypair, pk) = oracle_keypair();
        let emulated = script! {
            OP_SIZE
            600 OP_EQUALVERIFY
            OP_DROP
            1
        };
        let encoded = emulated.encode_sake_script(&[pk], 1).unwrap();
        let (mut tx, prevouts) = single_input_tx(ScriptBuf::new());

        // Build the carrier by hand: the checked constructor rejects this, so
        // the parser is tested with an explicitly malformed payload.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SAKE");
        payload.push(0); // version
        payload.push(0); // input index 0
        payload.push(1); // one element
        payload.extend_from_slice(&[0xfd, 0x58, 0x02]); // 600 as VarInt
        payload.extend_from_slice(&[0x42u8; 600]);
        let data = bitcoin::script::PushBytesBuf::try_from(payload).unwrap();
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(data),
        });

        let result = validate(&tx, &prevouts, &[SakeInput::new(0, encoded)]);
        assert!(matches!(result, Err(Error::InvalidWitnessCarriers(_))));
    }

    #[test]
    fn test_validate_accepts_520_byte_witness_element() {
        let (_secp, _keypair, pk) = oracle_keypair();
        let emulated = script! {
            OP_SIZE
            520 OP_EQUALVERIFY
            OP_DROP
            1
        };
        let encoded = emulated.encode_sake_script(&[pk], 1).unwrap();
        let (mut tx, prevouts) = single_input_tx(ScriptBuf::new());
        tx.output
            .push(TxOut::sake_witness_carrier(&[(0, vec![vec![0x42u8; 520]])]));

        assert!(validate(&tx, &prevouts, &[SakeInput::new(0, encoded)]).is_ok());
    }

    #[test]
    fn test_validate_multiple_witness_elements() {
        let (_secp, _keypair, pk) = oracle_keypair();
        let emulated = script! {
            OP_SIZE 400 OP_EQUALVERIFY OP_DROP
            OP_SIZE 400 OP_EQUALVERIFY OP_DROP
            OP_SIZE 400 OP_EQUALVERIFY OP_DROP
            1
        };
        let encoded = emulated.encode_sake_script(&[pk], 1).unwrap();
        let (mut tx, prevouts) = single_input_tx(ScriptBuf::new());
        tx.output.push(TxOut::sake_witness_carrier(&[(
            0,
            vec![vec![0xAAu8; 400], vec![0xBBu8; 400], vec![0xCCu8; 400]],
        )]));

        assert!(validate(&tx, &prevouts, &[SakeInput::new(0, encoded)]).is_ok());
    }

    #[test]
    fn test_control_block_commitment() {
        let (secp, _keypair, pk) = oracle_keypair();
        let internal_key = XOnlyPublicKey::from_str(
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let encoded = script! { OP_1 }.encode_sake_script(&[pk], 1).unwrap();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, encoded.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let control_block = spend_info
            .control_block(&(encoded.clone(), LeafVersion::TapScript))
            .unwrap();
        let prevout = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root()),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };
        tx.output.push(TxOut::sake_witness_carrier(&[(0, vec![])]));

        let input = SakeInput {
            input_index: 0,
            script: encoded.clone(),
            control_block: Some(control_block.clone()),
            spend_info: None,
        };
        assert!(
            validate(
                &tx,
                std::slice::from_ref(&prevout),
                std::slice::from_ref(&input)
            )
            .is_ok()
        );

        let tampered = SakeInput {
            input_index: 0,
            script: script! { OP_0 }.encode_sake_script(&[pk], 1).unwrap(),
            control_block: Some(control_block.clone()),
            spend_info: None,
        };
        assert!(matches!(
            validate(&tx, &[prevout], &[tampered]),
            Err(Error::ControlBlockMismatch { .. })
        ));

        // from_witness round-trip
        let mut witness = Witness::new();
        witness.push(encoded.as_bytes());
        witness.push(control_block.serialize());
        let parsed = SakeInput::from_witness(0, &witness).unwrap();
        assert_eq!(parsed.script, encoded);
        assert_eq!(parsed.control_block, Some(control_block));
    }

    #[test]
    fn test_ccv_minus_one_with_control_block() {
        let (secp, _keypair, oracle_pk) = oracle_keypair();
        let internal_key = XOnlyPublicKey::from_str(
            "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();

        // <data=data> <index=-1> <pk=-1> <taptree=-1> <mode=CHECK_INPUT>
        let emulated = script! {
            OP_0
            <-1>
            <-1>
            <-1>
            <-1>
            OP_CHECKCONTRACTVERIFY
            OP_1
        };
        let encoded = emulated.encode_sake_script(&[oracle_pk], 1).unwrap();

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, encoded.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let control_block = spend_info
            .control_block(&(encoded.clone(), LeafVersion::TapScript))
            .unwrap();
        let prevout = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root()),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };
        tx.output.push(TxOut::sake_witness_carrier(&[(0, vec![])]));

        let input = SakeInput {
            input_index: 0,
            script: encoded,
            control_block: Some(control_block),
            spend_info: None,
        };
        assert!(validate(&tx, &[prevout], &[input]).is_ok());
    }

    #[test]
    fn test_prevouts_count_mismatch() {
        let (_secp, _keypair, _pk) = oracle_keypair();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Default::default()],
            output: vec![],
        };
        let input = SakeInput::new(0, script! { OP_1 });
        assert!(matches!(
            validate(&tx, &[], &[input]),
            Err(Error::PrevoutsCountMismatch { .. })
        ));
    }

    #[test]
    fn test_invalid_input_index() {
        let (tx, prevouts) = single_input_tx(ScriptBuf::new());
        let input = SakeInput::new(9, script! { OP_1 });
        assert!(matches!(
            validate(&tx, &prevouts, &[input]),
            Err(Error::InvalidInputIndex { .. })
        ));
    }

    #[test]
    fn test_annex_is_rejected() {
        let mut witness = Witness::new();
        witness.push(vec![]); // stack
        witness.push(vec![0x51]); // script
        witness.push(vec![0x50, 0x42]); // annex-like last element
        assert!(matches!(
            SakeInput::from_witness(0, &witness),
            Err(Error::AnnexNotSupported { .. })
        ));
    }

    #[test]
    fn test_unbalanced_conditional_is_rejected() {
        // Core rejects scripts that end while an OP_IF is still open.
        let emulated = script! {
            OP_1
            OP_IF
            OP_1
        };
        assert_eq!(
            validate_single_script(emulated, vec![]),
            Err(Error::Exec(ExecError::UnbalancedConditional))
        );
    }

    #[test]
    fn test_stack_limit_is_enforced_after_pushes() {
        // 1001 minimal data pushes, then 1000 OP_DROP. Core rejects the
        // 1001st push; the emulator must not wait for the next opcode.
        let mut bytes = Vec::new();
        for _ in 0..1001 {
            bytes.push(0x01); // PUSHBYTES_1
            bytes.push(0x42);
        }
        bytes.resize(bytes.len() + 1000, 0x75); // OP_DROP
        let emulated = ScriptBuf::from_bytes(bytes);

        assert_eq!(
            validate_single_script(emulated, vec![]),
            Err(Error::Exec(ExecError::StackSize))
        );
    }

    #[test]
    fn test_five_byte_negative_script_number_is_rejected() {
        // -2147483647 - 1 needs a 5-byte minimal encoding. The next numeric
        // operation must reject it, like CScriptNum with a 4-byte limit.
        let emulated = script! {
            <-2147483647>
            1
            OP_SUB
            1
            OP_ADD
            OP_DROP
            1
        };

        assert_eq!(
            validate_single_script(emulated, vec![]),
            Err(Error::Exec(ExecError::ScriptIntNumericOverflow))
        );
    }

    #[test]
    fn test_nop4_and_nop5_are_nops() {
        assert!(validate_single_script(script! { OP_NOP4 OP_NOP5 OP_1 }, vec![]).is_ok());
    }

    #[test]
    fn test_unknown_pubkey_type_does_not_inspect_signature() {
        // BIP-342: a non-empty signature with an unknown key type succeeds
        // without parsing the signature, including its 65th sighash byte.
        let emulated = script! {
            <vec![0xAAu8; 33]>
            OP_CHECKSIG
        };

        for sighash_byte in [0x00u8, 0x04] {
            let mut sig = vec![0x01u8; 64];
            sig.push(sighash_byte);
            assert!(
                validate_single_script(emulated.clone(), vec![sig]).is_ok(),
                "unknown key type must ignore sighash byte {sighash_byte:#x}"
            );
        }
    }

    #[test]
    fn test_validate_rejects_empty_inputs() {
        let (tx, prevouts) = single_input_tx(ScriptBuf::new());
        assert_eq!(validate(&tx, &prevouts, &[]), Err(Error::NoInputs));
    }
}
