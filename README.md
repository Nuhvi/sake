# sake
Script Army Knife Emulator

## Limitations

- Only Taproot
- Only minimally encoded instructions
- No `Annex`
- `OP_CODESEPARATOR` is a nop
- `OP_CTLV` and `OP_CSV` are nops

## Acknowledgment

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
