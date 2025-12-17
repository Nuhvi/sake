use bitcoin::{
    Amount, ScriptBuf, Transaction, TxOut,
    hashes::Hash,
    key::Keypair,
    secp256k1::{Message, Secp256k1},
    sighash::{Prevouts, SighashCache},
};

use sake::{SakeWitnessCarrier, validate_and_sign};

mod test_helpers;
use test_helpers::ParseAsm;

#[test]
fn test_validate_and_sign_success() {
    let secp = Secp256k1::new();

    let secret_key = [0x42; 32];
    let keypair = Keypair::from_seckey_slice(&secp, &secret_key).unwrap();
    let public_key = keypair.x_only_public_key().0;

    // Input 0: Script that passes if witness is 1
    // Input 2: Script that passes if witness is 0
    let script0 = "OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF".parse_asm().unwrap();
    let script2 = "OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF".parse_asm().unwrap();

    // Sign the first and last inputs
    let scripts = vec![(0, script0), (2, script2)];

    // Data encoded in the OP_RETURN: [[ [1] ], [ [] ]]
    let sake_witness_carrier = ScriptBuf::new_sake_witness_carrier(&[
        vec![vec![1]], // For input 0: logic takes OP_IF path -> passes
        vec![vec![]],  // For input 1: logic takes OP_ELSE path -> passes
    ]);

    // MUST have at least 2 inputs because we are signing input 0 and 1
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![Default::default(), Default::default(), Default::default()],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: sake_witness_carrier, // The OP_RETURN output
        }],
    };

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
