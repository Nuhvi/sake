# sake
Script Army Knife Emulator

## How does it work

```rust
let emulation_witness = vec![
    // OP_CHECKSIGFROMSTACK inputs
    { signature }
    { message }

    // OP_CAT input
    { b"hello ".to_vec() }

    // Enable the emulation clause
    OP_1 
];


let oracles_witness = vec![
    // Two of 3 oracles' signatures
    { oracle_1_signature.to_vec() }
    { oracle_2_signature.to_vec() }

    // Disable the emulation clause and
    // use the oracles clause instead
    OP_0 
];

let locking_script = script!{
    // CTLV and CSV are OP_NOPs in the emulator.
    // So they have to happen before the OP_IF
    { 100 } 
    OP_CSV
    OP_DROP

    OP_EQUAL
    OP_IF
        // Emulate Script Army Knife Emulator

        // OP_CAT
        { b"world".to_vec() }
        OP_CAT
        { b"hello world".to_vec() }
        OP_EQUALVERIFY

        // OP_CHECKSIGFROMSTACK (OP_NOP9)
        { pubkey }
        OP_CHECKSIGFROMSTACK
        { 1 }
        OP_EQUALVERIFY

        { 1 }
    OP_ELSE
        // Until a soft fork taking over using OP_ACTIVATED (OP_NOP10),
        // Use OP_CHECKSIG or OP_CHECKSIGADD to verify oracle signatures.
        { oracle_1_pubkey }
        OP_CHECKSIG
        { oracle_2_pubkey }
        OP_CHECKSIGADD
        { oracle_3_pubkey }
        OP_CHECKSIGADD
        { 2 }
        OP_GREATERTHANOREQUAL

        { 1 }
    OP_ENDIF
}.compile();

```

## Limitations

- Only Taproot
- Only minimally encoded instructions
- No `Annex`
- `OP_CODESEPARATOR` is disabled
- `OP_CTLV` and `OP_CSV` are nops

## Acknowledgment

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
