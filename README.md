# sake
Script Army Knife Emulator

## How does it work

```rust
script!{
  // CTLV and CSV are OP_NOPs in the emulator.
  // So they have to happen before the OP_IF
  { 100 } 
  OP_CSV
  OP_DROP

  OP_0
  OP_SAKESUPPORTED // OP_NOP10
  OP_IF
      OP_DROP // Remove the remaining OP_0

      // Emulate Script Army Knife Emulator

      // OP_CAT
      { b"hello ".to_vec() }
      { b"world".to_vec() }
      OP_CAT
      { b"hello world".to_vec() }
      OP_EQUALVERIFY

      // OP_CHECKSIGFROMSTACK (OP_NOP9)
      { sig.to_vec() }
      { msg.to_vec() }
      { pk.to_vec() }
      OP_CHECKSIGFROMSTACK
      { 1 }
      OP_EQUALVERIFY

      { 1 }
  OP_ELSE
      // Until a soft fork taking over by enabling OP_SAKESUPPORTED,
      // Use OP_CHECKSIG or OP_CHECKSIGADD to verify oracle signatures.
      OP_CHECKSIG
      { 1 }
      OP_EQUALVERIFY

      { 1 }
  OP_ENDIF
};
```

## Limitations

- Only Taproot
- Only minimally encoded instructions
- No `Annex`
- `OP_CODESEPARATOR` is a nop
- `OP_CTLV` and `OP_CSV` are nops

## Acknowledgment

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
