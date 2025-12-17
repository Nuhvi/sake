use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

use sake::{SakeWitnessCarrier, validate};

mod test_helpers;
use test_helpers::ParseAsm;

#[test]
fn single_input() {
    let script = "OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF";

    let scripts = vec![(0, script.parse_asm().unwrap())];

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            // Skip adding an input, since we are not using sighash
        ],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_sake_witness_carrier(&[vec![vec![]]]),
        }],
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
        (0, "OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF".parse_asm().unwrap()),
        (1, "OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF".parse_asm().unwrap()),
    ];

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
        // Skip adding an input, since we are not using sighash
        ],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_sake_witness_carrier(&[vec![vec![]], vec![vec![1]]]),
        }],
    };

    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        // Skip creating a pay tot taproot pubkey
        script_pubkey: ScriptBuf::new_p2a(),
    }];

    validate(&tx, &prevouts, &scripts).unwrap();
}
