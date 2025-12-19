use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use bitcoin_script::script;

use sake::{SakeWitnessCarrier, validate};

#[test]
fn single_input() {
    let scripts = vec![
        // Input 0: Script that passes if witness is 0
        (0, script! { OP_IF { 0 } OP_ELSE { 1 } OP_ENDIF }.compile()),
    ];
    let witness_carrier = TxOut::sake_witness_carrier(&[
        (0, vec![vec![]]), // Ipnut 0 witness stack: [ OP_0 ]
    ]);

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            // Skip adding an input, since we are not using sighash
        ],
        output: vec![witness_carrier],
    };

    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        // Skip creating a pay tot taproot pubkey
        script_pubkey: ScriptBuf::new_p2a(),
    }];

    validate(&tx, &prevouts, &scripts).unwrap();
}

#[test]
fn two_inputs() {
    let scripts = vec![
        // Input 0: Script that passes if witness is 0
        (0, script! { OP_IF { 0 } OP_ELSE { 1 } OP_ENDIF }.compile()),
        // Input 1: Script that passes if witness is 1
        (1, script! { OP_IF { 1 } OP_ELSE { 0 } OP_ENDIF }.compile()),
    ];
    let witness_carrier = TxOut::sake_witness_carrier(&[
        (0, vec![vec![]]),  // Ipnut 0 witness stack: [ OP_0 ]
        (1, vec![vec![1]]), // Ipnut 1 witness stack: [ OP_1 ]
    ]);

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
        // Skip adding an input, since we are not using sighash
        ],
        output: vec![witness_carrier],
    };

    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        // Skip creating a pay tot taproot pubkey
        script_pubkey: ScriptBuf::new_p2a(),
    }];

    validate(&tx, &prevouts, &scripts).unwrap();
}
