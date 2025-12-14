use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

use sake::validate;

mod test_helpers;
use test_helpers::FromAsm;

#[test]
fn single_input() {
    let script = "OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF";
    let script_witnesses = "OP_RETURN OP_PUSHBYTES_2 0100";

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
        // Skip adding an input, since we are not using sighash
        ],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_asm(script_witnesses).unwrap(),
        }],
    };

    let scripts = vec![(0, ScriptBuf::from_asm(script).unwrap())];

    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        // Skip creating a pay tot taproot pubkey
        script_pubkey: ScriptBuf::new_p2a(),
    }];

    validate(&tx, &prevouts, &scripts).unwrap();
}

#[test]
fn two_inputs() {
    let script_witnesses = "OP_RETURN OP_PUSHBYTES_2 0100 OP_PUSHBYTES_3 010101";

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
        // Skip adding an input, since we are not using sighash
        ],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_asm(script_witnesses).unwrap(),
        }],
    };

    let scripts = vec![
        (
            0,
            ScriptBuf::from_asm("OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF").unwrap(),
        ),
        (
            1,
            ScriptBuf::from_asm("OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF").unwrap(),
        ),
    ];

    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        // Skip creating a pay tot taproot pubkey
        script_pubkey: ScriptBuf::new_p2a(),
    }];

    validate(&tx, &prevouts, &scripts).unwrap();
}
