# sake
Script Army Knife Emulator

## How does it work

```rust
use sake::EncodeSakeScript;

use bitcoin_script::{define_pushable, script};
define_pushable!();

// Emulated SAKE Script
let emulated_locking_script: ScriptBuf = script! {
    // Emulate Script Army Knife OpCodes:

    // OP_CAT (bip-347)
    <"world"> OP_CAT
    "hello world"> OP_EQUALVERIFY

    // OP_CHECKSIGFROMSTACK (bip-348)
    { pk }
    OP_CHECKSIGFROMSTACK
    OP_VERIFY

    { 1 }
}

// Native tapleaf script locking the utxo on-chain
let tapleaf_script = script!{
    // CTLV and CSV are OP_NOPs in the emulator,
    // So they have to happen before the emulated script.
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
        emulated_script.encode_sake_script(
            &[oracle_1_pubkey, oracle_2_pubkey, oracle_3_pubkey],
            2 // Threshold (2/3)
        )
    >
};

// Emulated witness stack, passed in the witness carrier
// (the last transaction output in the form of an OP_RETURN).
let emulation_witness = vec![
    // OP_CHECKSIGFROMSTACK inputs
    { signature }
    { message }

    // OP_CAT input
    <"hello ">
];

// The native taproot `Witness` passed to the network
// after collecting signatures from the oracles, after
// they validate they emulation witness.
let taproot_witness = vec![
    // Two of 3 oracles' signatures
    { oracle_1_signature.to_vec() }
    { oracle_2_signature.to_vec() }

    // .. script and control block..
];
```

## Limitations of the emulated script

- Only Taproot
- Only minimally encoded instructions
- `Annex` is not allowed
- `OP_CODESEPARATOR` is disabled (nop)
- `OP_CTLV` and `OP_CSV` are nops 
- `OP_SUCCESSX` causes the emulated script to fail instead of succeed
- Introspection and signatures will be based on the transaction before adding the witness carrier.

## Acknowledgment

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
