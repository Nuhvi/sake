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


let taproot_witness = vec![
    // Two of 3 oracles' signatures
    { oracle_1_signature.to_vec() }
    { oracle_2_signature.to_vec() }

    // .. script and control block..
];

let locking_script = script!{
    // CTLV and CSV are OP_NOPs in the emulator.
    // So they have to happen before the OP_IF
    100 OP_CSV OP_DROP

    // SAKE script encoded in the form of:
    // OP_PUSHBYTES_<len> 
    //      <4: "SAKE" | 1:VERSION | ..Encoded Emulated Script>
    // OP_DROP
    // 
    // OP_PUSHBYTES_32 <Oracle 1 Pubkey> OP_CHECKSIG
    // OP_PUSHBYTES_32 <Oracle 2 Pubkey> OP_CHECKSIGADD
    // OP_PUSHBYTES_32 <Oracle 3 Pubkey> OP_CHECKSIGADD
    // <threshold> OP_GREATERTHANOREQUAL
    < 
        // Emulated script
        script! {
            // Emulate Script Army Knife OpCodes:

            // OP_CAT (bip-347)
            <"world"> OP_CAT
            "hello world"> OP_EQUALVERIFY

            // OP_CSFSV: OP_CHECKSIGFROMSTACKVERIFY (OP_NOP5)
            { pk }
            OP_CHECKSIGFROMSTACKVERIFY
            OP_2DROP
            OP_DROP


            { 1 }
        }
        .try_into_sake_script(
            // Pubkeys
            &[oracle_1_pubkey, oracle_2_pubkey, oracle_3_pubkey],
            // Threshold
            2 
        )
    >
}.compile();

```

## Limitations of the emulated script

- Only Taproot
- Only minimally encoded instructions
- `Annex` is not allowed
- `OP_CODESEPARATOR` is disabled (nop)
- `OP_CTLV` and `OP_CSV` are nops 
- `OP_SUCCESSX` causes the emulated script to fail instead of succeed

## Acknowledgment

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
