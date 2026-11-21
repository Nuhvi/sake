# SAKE - Script Army Knife Emulator

**SAKE** enables Bitcoin developers to write and deploy scripts using proposed opcodes (like `OP_CAT`, `OP_CHECKSIGFROMSTACK`, `OP_TEMPLATEHASH`, `OP_CHECKCONTRACTVERIFY`, `OP_AMOUNT`) that haven't been activated yet—without waiting for a soft fork. It achieves this by trusting blind oracles, selected by the user/developer with no setup or ceremony.

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [What is Script Army Knife?](#what-is-script-army-knife)
- [Architecture](#architecture)
- [Complete Example](#complete-example)
- [Witness Carrier Format](#witness-carrier-format)
- [Oracle Validation](#oracle-validation)
- [Use Cases](#use-cases)
- [Limitations](#limitations)
- [Trust Model](#trust-model)
- [FAQ](#faq)
- [Acknowledgments](#acknowledgments)

## Overview

**SAKE** implements the **Script Army Knife** framework proposed by Salvatore Ingala, a balanced approach between simplicity and expressiveness for Bitcoin tapscript. Rather than waiting for consensus changes, SAKE allows immediate experimentation through oracle-validated script emulation.

**Key Features:**
- Write scripts using proposed Bitcoin opcodes today
- Oracle-validated execution with more flexibility than federated bridges
- Taproot-based with flexible fallback conditions
- Compatible with existing Bitcoin infrastructure
- Evidence of oracle misbehavior is cryptographically verifiable on-chain
- Run an Oracle to help Bitcoin development, without the custodial liability
- Show the community the demand for your use-case, right on-chain.

## How It Works

### Transaction Parts

1. **Emulated Script**: The tapscript with extra op_codes you want to lock your input to, encoded in the native tapscript (for observability) and immediately dropped from the stack.
2. **Oracles basic Multisig**: The oracles public keys and the threshold required to sign the transaction to spend the input.
3. **Witness Carrier**: An `OP_RETURN` output containing the witness data for the emulated script, necessary to be signed so the oracles must commit to the witness they have evaluated.

### Transaction Flow

#### Step 1: Lock UTXO
User creates Taproot output with:
 - Encoded SAKE script (emulated logic)
 - Oracle public keys (e.g., 2-of-3)
 - Optional: Alternative tapleafs for fallback/recovery

#### Step 2: Create Spending Transaction
User constructs transaction:
 - Inputs: Spend the locked UTXO
 - Outputs: Desired outputs
 - Last Output: Witness Carrier (OP_RETURN with emulation witness)

#### Step 3: Send to Oracles
The user sends the transaction, the prevouts, and for each SAKE input the last
two elements of its taproot witness: the tapscript and the control block.
  - The transaction has empty input witnesses; the emulation stack is in the witness carrier
  - The oracle verifies each control block against its prevout
  - No coordination between oracles needed
  - Each oracle validates independently

#### Step 4: Oracle Validation (Independent & Parallel)
Each oracle:
1. Parses the witness carrier from the last output
2. Builds each input with `SakeInput::from_witness` from `[tapscript, control_block]`
3. Verifies each control block against the prevout
4. Extracts the SAKE encoding from each supplied tapscript
5. Removes the witness carrier from the transaction used for emulation
6. Runs the emulation engine with the carrier's witness stacks
7. If valid → signs the taproot script-spend sighash | If invalid → rejects

Non-SAKE inputs are not validated and are not signed. The oracle only
attests to inputs that contain a SAKE encoding.

#### Step 5: Collect Signatures
User collects threshold signatures from oracles
 - Constructs Taproot witness for each input with emulated script

#### Step 6: Broadcast to Bitcoin Network
Bitcoin nodes validate:
 - Native Taproot script (oracle signatures + threshold)
 - Standard Bitcoin consensus rules
 - ✓ Transaction confirmed

**Important**: Oracles are stateless and don't need to communicate with each other, query the blockchain, or perform any setup ceremony. They can operate in TEEs (Trusted Execution Environments) for additional security.

## What is Script Army Knife?

Script Army Knife (SAK) is a framework proposed by Salvatore Ingala that provides a minimal yet powerful set of opcodes for Bitcoin. It strikes a balance between:
- **Simplicity**: Fewer opcodes than full script restoration or Simplicity
- **Expressiveness**: More powerful than OP_CAT-only or OP_CTV-only approaches
- **Practicality**: Sufficient for real-world covenant applications

### The Five Core Opcodes

Script Army Knife consists of five carefully chosen opcodes that work together to enable flexible covenant construction:

#### 1. **OP_CAT** (Vector Commitments) [BIP 347](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
*Concatenates two stack elements*

- Generalizes 'hashlocks' to collections
- Allows to create Merkle trees
- Taptrees do it for Scripts
- Mostly useful in combination with other primitives.

#### 2. **OP_CHECKSIGFROMSTACK** (Signature Verification) [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)
*Verifies a signature on arbitrary stack data*

- Delegation
- Oracles
- Equivocation

**Example use:** Verify an oracle's signature on a price feed or timestamp without requiring the oracle to sign the entire transaction.

#### 3. **OP_CHECKCONTRACTVERIFY** (State-carrying UTXOs) [BIP 443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki)
*Verifies that transaction satisfies a contract specified on the stack*

- On-chain multi-party protocols
- Multi-step transactions; reactive security
- Settlement protocols for L2s/bridges

#### 4. **OP_TEMPLATEHASH** (Next-Transaction Commitment) [BIP-446](https://github.com/bitcoin/bips/pull/1974/changes#diff-1dc83010a8fe1e5e76261fa4dc2b5ada14da9f7f0dfe967c0b5049bf8542ac54)
*Pushes a hash of specific transaction fields to the stack*

- Useful to represent outcomes or terminal states

#### 5. **OP_AMOUNT** (Amount introspection) [BIP-pr#2069](https://github.com/bitcoin/bips/pull/2069/files#bip-op-amount.md)
*Pushes the amount of the current input, or a specific input or specific output to the stack*

Mostly useful in combination with other primitives
- Inputs: velocity limits
- Outputs: fine-grained payouts

### Why These Five?

This specific combination was chosen because:

1. **Completeness**: Together, they enable the full range of covenant patterns (vaults, payment channels, fraud proofs, bridges)
2. **Minimalism**: Fewer opcodes than alternative proposals, reducing consensus change complexity

### Comparison to Other Proposals

| Proposal | Engineering effort | Ergonomicity | Status |
|----------|-----------|----------------|--------|
| OP_CAT only | Low |  Very Low | BIP-347 |
| **Script Army Knife** | Medium | High | BIPs (347/348/443/446/??) |
| Elements/Liquid opcodes | Very High | Very High | In production |
| Great Script Restoration | Very High | High | WIP |
| Simplicity | Entire new paradigm | Very High | still under development |

Script Army Knife sits in the "sweet spot"—powerful enough for practical covenants, simple enough for consensus.

### Real-World Applications Enabled

With these five opcodes, you can build:

- **Vaults**: Time-locked withdrawals with amount limits and emergency recovery
- **Payment Pools**: Shared UTXO management with off-chain updates
- **Fraud Proofs**: Optimistic rollups and validity challenges (MATT-style)
- **Bridges**: Cross-chain asset transfers with cryptographic verification
- **Congestion Control**: Fee-efficient transaction batching and consolidation
- **State Channels**: Lightning-like channels with more flexible state transitions
- **Covenants**: Recursive spending restrictions and coin coloring

## Architecture

The `sake` crate provides three main components:

1. **EncodeSakeScript**: Converts emulated scripts to native Bitcoin scripts (version 0 single push or version 1 chunked)
2. **SakeWitnessCarrier**: Encodes witness stacks in an `OP_RETURN` `TxOut`
3. **SakeInput / validate_and_sign()**: Describes each input's tapscript and control block; validates SAKE inputs and produces script-spend signatures at the oracle side.

### For Users

```rust
use sake::{EncodeSakeScript, SakeWitnessCarrier};

use bitcoin_script::{define_pushable, script};
define_pushable!();

// Create emulated script
let emulated_script = script! { /* your logic */ };

// Encode into native taproot script
let taproot_script = script! {
    // CSV or CLTV opcodes go first, as they can't be enforced in the emulator
    100 OP_CSV OP_DROP  
    <emulated_script.encode_sake_script(&[oracle_pk], 1).unwrap()>
};

// Add witness carrier to transaction
let witness_carrier = TxOut::sake_witness_carrier(&[
    (
        0, // Input index 
        vec![], // Witness stack (elements except for script, control block or annex)
    )
])
    .expect("valid SAKE witness carrier");
tx.output.push(witness_carrier);
```

### For Oracles

```rust
use bitcoin::Witness;
use sake::{SakeInput, validate_and_sign};

// `from_witness` is the only public constructor. It takes the taproot witness
// with the script and control block as the last two elements. It rejects an
// annex and extracts the control block, so `validate` can check the commitment.
let witness = Witness::from_slice(&[
    taproot_script.to_vec(),
    control_block.serialize(),
]);
let input = SakeInput::from_witness(0, &witness)?;

// Only inputs with a SAKE encoding are validated and signed.
// Returns (input_index, script-spend SIGHASH_DEFAULT signature) pairs.
let signatures = validate_and_sign(keypair, &tx, &prevouts, &[input])?;
```

## Complete Example

Here's a complete example showing a covenant that requires:
- `OP_CAT` to construct a message
- `OP_CHECKSIGFROMSTACK` to validate a signature on that message  
- `OP_TEMPLATEHASH` to enforce transaction structure
- 2-of-3 oracle validation

```rust
use sake::{EncodeSakeScript, SakeWitnessCarrier};
use sake::{OP_AMOUNT_CURRENT_INPUT_SELECTOR, op_amount_input_selector, op_amount_output_selector};
use bitcoin::Witness;
use bitcoin_script::{define_pushable, script};

define_pushable!();

// Step 1: Define the emulated logic
let emulated_script: ScriptBuf = script! {
    // Construct message by concatenating stack elements
    <"world"> OP_CAT
    <"hello world"> OP_EQUALVERIFY
    
    // Verify signature on the constructed message
    <pk>
    OP_CHECKSIGFROMSTACK
    OP_VERIFY
    
    // Enforce transaction template
    OP_TEMPLATEHASH
    <template_hash>
    OP_EQUALVERIFY

    // Check current input amount
    <OP_AMOUNT_CURRENT_INPUT_SELECTOR> // Zero
    OP_AMOUNT
    <expected_current_input_amount>
    OP_EQUALVERIFY

    // Check first input amount
    <op_amount_input_selector(0)> // -1
    OP_AMOUNT
    <expected_first_input_amount>
    OP_EQUALVERIFY

    // Check first output amount
    <op_amount_output_selector(0)> // 1
    OP_AMOUNT
    <expected_first_output_amount>
    OP_EQUALVERIFY
    
    { 1 }  // Success
};

// Step 2: Create the native taproot script
let taproot_script = script! {
    // Native opcodes (CSV, CLTV) must come before emulated script
    100 OP_CSV OP_DROP
    
    // Encoded SAKE script:
    // Format: PUSHBYTES("SAKE" | VERSION | <emulated_script_bytes>)
    //         OP_DROP
    //         <oracle_1_pk> OP_CHECKSIG
    //         <oracle_2_pk> OP_CHECKSIGADD
    //         <oracle_3_pk> OP_CHECKSIGADD
    //         <threshold> OP_GREATERTHANOREQUAL
    <emulated_script.encode_sake_script(
        &[oracle_1_pk, oracle_2_pk, oracle_3_pk],
        2  // 2-of-3 threshold
    ).unwrap()>
};

// Step 3: Prepare the emulation witness (in reverse stack order)
let emulation_witness = vec![
    signature.to_vec(),   // OP_CHECKSIGFROMSTACK signature
    message.to_vec(),     // OP_CHECKSIGFROMSTACK message
    <"hello ">,           // OP_CAT input
];

// Step 4: Create the spending transaction
let mut spending_tx = Transaction {
    input: vec![/* spend the locked UTXO */],
    output: vec![/* your outputs */],
    /* ... */
};

// Add witness carrier as the last output
spending_tx
    .output
    .push(TxOut::sake_witness_carrier(&[(0, emulation_witness)])?);

// Step 5: Send to oracles for validation
// The input is built from the taproot witness: [stack..., script, control_block].
let sake_witness = Witness::from_slice(&[
    taproot_script.to_vec(),
    control_block.serialize(),
]);
let sake_input = sake::SakeInput::from_witness(0, &sake_witness)?;
let signatures = sake::validate_and_sign(keypair, &spending_tx, &prevouts, &[sake_input])?;
// Each oracle returns (input_index, SIGHASH_DEFAULT script-spend signature) pairs.

// Step 6: Construct final witness with oracle signatures
// A 2-of-3 script has three CHECKSIG/CHECKSIGADD ops, so the witness
// needs three signature slots. Use an empty element for a non-signer.
let taproot_witness = Witness::from_slice(&[
    vec![],                       // oracle 3 did not sign
    oracle_2_signature.to_vec(),  // pk2 slot
    oracle_1_signature.to_vec(),  // pk1 slot (top of the stack)

    taproot_script.to_vec(),      // Script
    control_block.serialize(),    // Control block
]);

spending_tx.input[0].witness = taproot_witness;

// Step 7: Broadcast to Bitcoin network
// The network validates the native taproot script only
```

## Witness Carrier Format

The witness carrier is always the **last output** in the transaction, formatted as:

```
OP_RETURN <data>
```

Where `<data>` starts with the following header, followed by one group per
SAKE input:
```
"SAKE" (4 bytes)
| VERSION (1 byte)
| INPUT_INDEX (VarInt) - which input this witness is for
| NUM_ELEMENTS (VarInt) - how many stack elements
| [ELEMENT_LENGTH (VarInt) | ELEMENT_DATA (bytes)]...
```

The `"SAKE"` prefix and `VERSION` are written once, not once per input.
Each stack element is at most 520 bytes and each stack has at most 1000
elements (the BIP-342 initial stack limits). The whole payload is a single
push in the `OP_RETURN` output, so the output script itself can be larger
than 520 bytes.

This encodes witness stacks as: `Vec<(usize, Vec<Vec<u8>>)>` where:
- `usize` = input index
- `Vec<Vec<u8>>` = stack elements for that input

**Important**: The witness carrier is added after generating the transaction but
removed before emulation. It does not affect emulated `OP_TEMPLATEHASH`,
introspection, or emulated signature checks. The oracle signatures are over the
real transaction, including the carrier output.

## Oracle Validation

### Oracle Responsibilities

1. Receive the transaction, prevouts, and each SAKE input's taproot witness
   (`[stack..., tapscript, control_block]`)
2. Parse the witness carrier from the last output
3. Build each input with `SakeInput::from_witness` and verify its control block
   against the prevout. The constructor rejects an annex and always extracts
   the control block, so validation always checks the taproot commitment.
4. Extract the SAKE encoding from the tapscript
5. Run the emulation engine with the carrier's witness stack
6. If emulation succeeds, sign the tapscript script-spend sighash (`SIGHASH_DEFAULT`)
7. Return `(input_index, signature)` to the user

Native (non-SAKE) inputs are not executed, validated, or signed.

### Oracle Independence

- **No coordination**: Oracles don't communicate with each other
- **No state**: Each validation is independent; the oracle gets the prevouts and tapscripts from the request and needs no blockchain queries
- **No setup**: No threshold key generation or DKG ceremonies
- **TEE-compatible**: Can run in isolated environments

### Accountability

If an oracle signs an invalid transaction:
- **Evidence is on-chain**: The transaction itself contains the emulated script (in the spending script) and witness carrier (in outputs)
- **Evidence is signed**: The oracle's signature covers this invalid state
- **Slashable**: Can be proven objectively to smart contracts on Ethereum, Liquid, Rootstock, Starknet, etc.

### Trust Flexibility

Users choose their own oracles and can:
- Add fallback spending paths to other oracles in alternative tapleafs
- Include time-locked recovery paths that bypass oracles entirely
- Lock funds to oracle keys without the oracles being aware
- Switch oracle sets over time

## Use Cases

SAKE enables any covenant construction possible with the [MATT (Merkelize All The Things)](https://merkle.fun/) proposal.

### Example: Simple Vault

```rust
let vault_scripts = vec![
    script! {
        // Emergency path: anyone can spend after 1 year
        <52560> OP_CSV OP_DROP  // ~1 year
        /* .. */
    },
    script! {
        // Normal withdrawal: requires 7-day delay + template
        <1008> OP_CSV OP_DROP  // ~7 days

        script!{
            OP_TEMPLATEHASH
            <withdrawal_template>
            OP_EQUAL
        }.encode_sake_script(
            &[oracle_1_pubkey, oracle_2_pubkey, oracle_3_pubkey],
            2 // Threshold (2/3)
        )
    }
];
```

### Example: Stateful Contract (Append-Only Log)

`OP_CHECKCONTRACTVERIFY` enables UTXOs that carry state: the UTXO's taproot key encodes both the contract logic (taptree) and the current state (data tweak). Each spend must produce an output whose key reflects the updated state, cryptographically enforcing valid transitions.

The pattern works as follows. A UTXO is created whose taproot output key is `tweak(naked_key, current_state)`. To spend it, the script verifies the input's key matches the claimed old state, computes the new state in script, and verifies the output's key matches `tweak(naked_key, new_state)`. Anyone attempting to spend with a false old state will fail the input check; anyone producing an output with a tampered new state will fail the output check.

```
         Input UTXO                        Output UTXO
   ┌──────────────────────┐          ┌──────────────────────────────────────────┐
   │ key = tweak(K, s0)   │  spend   │ key = tweak(K, s1)                       │
   │                      │ ──────►  │                                          │
   │ s0 = old_accumulator │          │ s1 = sha256(old_accumulator │| new_data) │
   └──────────────────────┘          └──────────────────────────────────────────┘
          verified by                               enforced by
        CCV CHECK_INPUT                          CCV CHECK_OUTPUT
```

The script uses `OP_CAT` + `OP_SHA256` to construct the `new_accumulator` from witness-supplied data and `OP_CHECKCONTRACTVERIFY` in both CHECK_INPUT and CHECK_OUTPUT modes to enforce the transition:

```rust
// State: a byte string that grows by appending each round.
// The UTXO key = taptweak(data_tweak(NUMS_KEY, current_state), taptree).
// Witness provides: [append_data, old_state]

let contract_script = script! {
    // old_state is on top of stack (from witness).
    // Duplicate it: one copy for the input check, one for OP_CAT.
    OP_DUP

    // Verify the INPUT encodes old_state in its key.
    // CCV computes: tweak(NUMS_KEY, old_state) + taptweak(taptree)
    // and checks it matches prevout[current_input].scriptPubKey.
    <-1>                            // index = current input
    <BIP341_NUMS_KEY>               // naked key
    <taptree>                       // same taptree carried forward
    <CCVMode::CheckInput as i64>    // mode = CHECK_INPUT
    OP_CHECKCONTRACTVERIFY

    // Stack: [append_data, old_state]
    // Compute new_state = old_state || append_data
    OP_SWAP
    OP_CAT                          // Stack: [new_state]
    OP_SHA256                       // Stack: new_accumulator

    // Verify the OUTPUT encodes new_state in its key.
    // CCV computes: tweak(NUMS_KEY, new_state) + taptweak(taptree)
    // and checks it matches tx.output[0].scriptPubKey,
    // and that output[0].value >= input residual (amount preserved).
    OP_0                            // index = output 0
    <BIP341_NUMS_KEY>               // same naked key
    <taptree>                       // same taptree — contract logic is unchanged
    <CCVMode::CheckOutput as i64>   // mode = CHECK_OUTPUT (default amount: preserve residual)
    OP_CHECKCONTRACTVERIFY

    OP_1
};
```

Each spend appends append_data (supplied in the witness) to the running state. The taptree is preserved unchanged across transitions, meaning the contract logic itself is immutable — only the data tweak evolves and accumulates.

This pattern enables a smart contract to (for example) keep track of a sidechain competing forks, then use a STARK proof using `OP_CAT` and `OP_TEMPLATEHASH` in a different tapscript path to prove that the heaviest sidechain authorized the withdrawal of a certain amount of funds.

The same pattern generalises to any deterministic state machine — a counter, a balance sheet, a game board — where the state is hashed or committed before being encoded in the key.

## Limitations

SAKE operates within specific constraints to maintain compatibility and security:

### Technical Constraints

- **Taproot only**: Only works with P2TR outputs
- **Minimal encoding**: All emulated script instructions and numbers must be minimally encoded
- **No Annex**: `SakeInput::from_witness` rejects annex-bearing witnesses. An annex added to the final spend invalidates the oracle signature.
- **No OP_CODESEPARATOR**: Rejected by the emulator
- **SAKE inputs only**: The oracle validates and signs inputs that contain a SAKE encoding. Native tapscripts are not validated.
- **Script size**: Version-0 encodings fit a single push (up to 515 script bytes). Larger scripts use version-1 chunked encoding; every push is at most 520 bytes and the total is bounded by the block weight.
- **Witness elements**: The carrier stack is limited to 520 bytes per element and 1000 elements.
- **Oracle count**: At most 1000 oracle keys. The native tapscript needs one initial stack element per oracle signature, and BIP-342 limits the initial stack to 1000 elements.

### Emulation Behavior

- **OP_CSV and OP_CLTV are NOPs**: They must be placed in the native script, before the encoded SAKE script. The oracle does not validate timelocks.
- **OP_SUCCESSx → FAIL**: Implemented replacements are `OP_CAT`, `OP_CSFS`, `OP_CCV`, `OP_TEMPLATEHASH`, and `OP_AMOUNT`. Other `OP_SUCCESSx` opcodes fail when executed; the legacy disabled opcodes and `OP_RESERVED` fail even in unexecuted branches.
- **Pre-carrier introspection**: Signature and introspection opcodes operate on the transaction *without* the witness carrier
- **Sigop budget**: The emulator charges one signature opcode per 50 bytes of the serialized witness-carrier stack, plus one free signature opcode. It does not use the native witness size.

## Trust Model

### Non-Custodial

Oracles are **not custodians**:
- They are not involved in the locking of funds to scripts that require their signatures
- They only validate and sign inputs that contain a SAKE encoding; native tapscripts are outside their attestation
- They cannot steal funds before they are told which script locks them
- After disclosure, a malicious oracle (or a malicious threshold of oracles) can sign a conflicting spend. The native script only enforces the oracle signatures, not the emulated rules.
- They cannot prevent alternative spending paths
- They can refuse to sign (liveness failure)
- Users must use a threshold and should add fallback conditions for oracle failures

### Transparent

- All oracle misbehavior is cryptographically provable
- Evidence exists on-chain in the transaction itself
- Signatures prove oracle accountability
- Can integrate with slashing mechanisms on other chains

### User-Controlled

- Users choose which oracles to trust
- Can update oracle sets via alternative tapleafs
- Can include time-locked escape hatches
- Can lock funds without oracle awareness

## FAQ

### General Questions

**Q: Is SAKE a soft fork proposal?**  
A: No. SAKE is an emulation layer that works on Bitcoin today without any consensus changes. It allows testing and using Script Army Knife opcodes while waiting for (or instead of) a soft fork.

**Q: Do I need to trust oracles with my funds?**  
A: No. Oracles don't hold your funds. But depending on your Taproot tree, and how many oracles you are using, they might be able to collude and steal the funds, so it is better to use blinded oracles using TEEs, or use as many reputable oracles as you can, or make sure to only use emulated scripts as a fallback after a timeout, so you only need them in rare cases.
Note that locking funds to an emulated script doesn't require any ceremony so oracles don't get any notification that they can spend the funds you locked to that taproot address. And in the happy case where you don't need their help, they may never know.

**Q: Can oracles censor my transactions?**  
A: Individual oracles can refuse to sign, but if you use a threshold (e.g., 2-of-3), you only need enough honest oracles to meet the threshold. You can also rotate oracle sets or add time-locked escape hatches.

**Q: What happens if an oracle signs an invalid transaction?**  
A: The evidence of misbehavior is cryptographically provable and exists on-chain. This can be used to slash bonds on other chains (Ethereum, Liquid, Rootstock, etc.) where the oracle has posted collateral. But at the very least they will lose reputation and any future fees.

**Q: How much does SAKE cost to use?**  
A: You pay standard Bitcoin transaction fees plus the cost of one additional `OP_RETURN` output (witness carrier). Oracle fees depend on the oracle service you choose.

**Q: Should I use SAKE or wait for soft forks?**  
A: One of the main purposes of SAKE is to provide the on-chain evidence of the demand and safety of such upgrades, so I encourage you to hack against SAKE and share your projects, as a signal to the community.

**Q: Can SAKE scripts be converted to native scripts after a soft fork?**  
A: Yes! If Script Army Knife opcodes are activated, you can create a direct translation by extracting the emulated script and using it as a native script, removing the oracle requirement, however you will need the Oracles' cooperation or a fallback tapleaf to move the funds to the new native covenant.

### Technical Questions

**Q: Why is there a witness carrier instead of the witness field within a disabled OP_IF?**
A: To optionally slash Oracles for signing and publishing invalid transactions according to SAKE rules, we need a compact stateless fraud proof — small enough to verify on-chain in an EVM or BitVM contract. Segregated Witness is not committed to in the Sighash, so it can't serve this role. The Annex is non-standard and poorly propagated, making OP_RETURN the most suitable witness carrier.

**Q: Why is the witness carrier always the last output?**  
A: This is a convention that simplifies parsing and ensures the carrier doesn't interfere with covenant logic that might count or introspect outputs.

**Q: Can I use OP_CSV and OP_CLTV in SAKE scripts?**
A: They must be placed in the native script *before* the encoded SAKE script. They are NOPs in the emulator, so the oracle does not check them; Bitcoin consensus enforces them. Because an oracle is stateless, it cannot check UTXO age (CSV) or the current chain height/time (CLTV) anyway.

**Q: Why doesn't the witness carrier affect OP_TEMPLATEHASH?**  
A: The carrier is removed before emulation so introspection and emulated signature checks operate on the transaction that the covenant constrains, without the carrier. The oracle signature is over the real transaction with the carrier, so the carrier is covered by the oracle threshold.

**Q: Can I nest SAKE scripts?**  
A: No. Each SAKE script is validated independently by oracles. However, you can create complex covenants by chaining transactions with different SAKE scripts.

**Q: What's the maximum size of an emulated script?**
A: Encoding version 0 stores the script in a single tapscript push, so it is limited to 515 bytes (520 minus the 5-byte SAKE header). Version 1 splits larger scripts into 520-byte chunk pushes; the practical limit is the block weight.

**Q: Can SAKE scripts access the blockchain state?**  
A: No. SAKE scripts operate only on transaction data (inputs, outputs, witness data). They cannot query UTXOs, block headers, or other blockchain state, nor can they enforce CSV or CLTV. For the same reason, the oracle does not validate native tapscripts.

### Comparison Questions

**Q: How does SAKE compare to BitVM?**  
A: BitVM shines at two-party contracts, but for any multiparty contracts, it depends on a covenant committee to emulate `OP_TEMPLATEHASH`, assuming 1-of-n honest members, then it uses a limited set of operators that can bridge the funds out/settle back to native Bitcoin, so you still have to trust the liveness of these operators. In exchange, you have to contend with significant complexity, and you can't reuse this setup for anything else. SAKE in exchange is much simpler, but may require trust assumptions much similar to federated bridges if no fallback spending path is available, however, once trust worthy Oracles are established, they can be used for anything without their involvement, while their code remains simple, and their liabilities very very limited, unlike custodial bridges.

**Q: How does SAKE compare to Liquid/Rootstock/WrappedBitcoin?**  
A: all federated bridges have four main limitations compared to SAKE:
1. They can only bridge you to a specific blockchain(s).
2. They are custodial, and have all the legal liability and operational cost that that requires.
3.  They have to run software watching both Bitcoin and the other blockchains they bridge to.
4. They are preset, and you can't choose to combine some of each federation into one trusted set of oracles.
In comparison, a SAKE oracle can run in a stateless mode in a TEE doing nothing but signing a transaction they receive through an HTTP request, knowing nothing about Bitcoin, or any other system.

**Q How does SAKE compare to confidential-script?**
SAKE is somewhat the opposite of [confidential-script](https://github.com/joshdoman/confidential-script-lib), as in it favors observability than confidentiality. By having the script and its witness observable on-chain, malicious oracles can be held accountable, and the community can examine the use-cases and security of Script Army Knife proposal and reason about a soft fork enabling it in the future. That being said, SAKE also encourages the use of TEE as a part of defence in depth strategy.

**Q: How does SAKE compare to blind-vault?**

Similar to the previously discussed confidential-script, [Blind-vault](https://github.com/halseth/blind-vault) aims for privacy instead of observability, furthermore the blind signer is verifying a general purpose program (compiled to RISC-V) as opposed to Bitcoin Script.

### Security Questions

**Q: What if all my oracles disappear?**  
A: Include alternative tapleafs with time-locked recovery paths or fallback to different oracle sets. Never lock funds without a recovery mechanism.

**Q: Can an oracle front-run my transaction?**  
A: Oracles see your transaction before signing, and they can see the control block after the transaction is broadcasted, so theoretically yes they can spend that same leaf script again if the taproot address is reused. 
Use multiple independent oracles and threshold signatures to reduce this risk. 
Consider using **TEE**-based oracles, and or oracles that have slashable bonds on other networks.

**Q: Why does the witness carrier use OP_RETURN instead of the Taproot annex?**
A: The annex would be preferable place for this data, but annex-bearing transactions are non-standard and won't relay across the p2p network today, and might carry a prohibitive meaning in a future soft fork. OP_RETURN outputs have no risk of acquiring new meaning, relay without issue, and recently the OP_RETURN size limit in most relay nodes have became significantly more liberal.

## Acknowledgments

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
The Script Army Knife proposal is by [Salvatore Ingala](https://salvatoshi.com/).

## License

Licensed under the [MIT License](LICENSE).
