use bitcoin::{
    Amount, ScriptBuf, Transaction, TxOut,
    hashes::Hash,
    key::Keypair,
    secp256k1::{Message, Secp256k1},
    sighash::{Prevouts, SighashCache},
};
use bitcoin_script::script;

use sake::{SakeWitnessCarrier, validate_and_sign};

#[test]
fn test_validate_and_sign_success() {
    // Sign the first and last inputs
    let scripts = vec![
        // Input 0: Script that passes if witness is 1
        (0, script! { OP_IF { 1 } OP_ELSE { 0 } OP_ENDIF }.compile()),
        // Input 2: Script that passes if witness is 0
        (2, script! { OP_IF { 0 } OP_ELSE { 1 } OP_ENDIF }.compile()),
    ];

    // Data encoded in the OP_RETURN: [[ [1] ], [ [] ]]
    let witness_carrier = ScriptBuf::new_sake_witness_carrier(&[
        vec![vec![1]], // Ipnut 0 witness stack: [ OP_1 ]
        vec![vec![]],  // Ipnut 2 witness stack: [ OP_0 ]
    ]);

    // MUST have at least 2 inputs because we are signing input 0 and 1
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![Default::default(), Default::default(), Default::default()],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: witness_carrier, // The OP_RETURN output
        }],
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
