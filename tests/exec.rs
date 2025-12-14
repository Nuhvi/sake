use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, hex::DisplayHex, sighash::SighashCache};

use sake::exec::Exec;

mod test_helpers;
use test_helpers::FromAsm;

#[test]
fn basic() {
    let script_asm = "OP_IF OP_2 OP_ELSE OP_4 OP_4 OP_CAT OP_ENDIF";

    let script = ScriptBuf::from_asm(script_asm).expect("error parsing script");
    println!(
        "Script in hex ({} bytes): {}",
        script.as_bytes().len(),
        script.as_bytes().to_lower_hex_string(),
    );

    let script_witness: Vec<Vec<u8>> = vec![vec![]];

    let script_witness_bytes = script_witness.join::<&[u8]>(&[]);
    println!(
        "Script witness in hex ({} bytes): {}",
        script_witness_bytes.len(),
        script_witness_bytes.to_lower_hex_string(),
    );

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let mut sighashcache = SighashCache::new(tx);

    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_p2a(),
    }];

    let mut exec = Exec::new(&mut sighashcache, &prevouts, 0, &script, script_witness)
        .expect("error creating exec");

    loop {
        println!(
            "Remaining script: [{}]",
            exec.remaining_script().to_asm_string()
        );
        println!("Stack: [{}]", exec.stack());
        println!("AltStack: [{}]", exec.altstack());
        println!("--------------------------------------------------");

        let next = exec.exec_next();
        if next.is_err() {
            println!("Error {next:?}");
            break;
        }
    }

    let result = exec.result().unwrap();

    println!("Result [{}]", result.final_stack);

    assert!(result.success);
    assert_eq!(result.final_stack.to_string(), "1028");
}
