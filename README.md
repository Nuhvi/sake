# SAKE - Script Army Knife Emulator

**SAKE** enables Bitcoin developers to write and deploy scripts using proposed opcodes (like `OP_CAT`, `OP_CHECKSIGFROMSTACK`, `OP_TEMPLATEHASH`, `OP_CONTRACTVERIFY`, `OP_AMOUNT`) that haven't been activated yet—without waiting for a soft fork. It achieves this by trusting blind oracles, selected by the user/developer with no setup or ceremony.

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
User send the transaction, prevouts and scripts to each oracle
 - Oracles receive the transaction (with empty Witnesses)
 - No coordination between oracles needed
 - Each oracle validates independently
                          
#### Step 4: Oracle Validation (Independent & Parallel)
Each oracle:
1. Extracts witness carrier from last output
2. Extracts encoded SAKE script from each spending input
3. Removes witness carrier from transaction
4. Runs emulation engine with witness stacks
5. If valid → signs transaction | If invalid → rejects

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

- Generalizes ‘hashlocks’ to collections
- Allows to create Merkle trees
- Taptrees do it for Scripts
- Mostly useful in combination with other primitives.

#### 2. **OP_CHECKSIGFROMSTACK** (Signature Verification) [BIP 348](https://github.com/bitcoin/bips/blob/master/bip-0348.md)
*Verifies a signature on arbitrary stack data*

- Delegation
- Oracles
- Equivocation

**Example use:** Verify an oracle's signature on a price feed or timestamp without requiring the oracle to sign the entire transaction.

#### 3. **OP_TEMPLATEHASH** (Next-Transaction Commitment) [BIP-pr#1974](https://github.com/bitcoin/bips/pull/1974/files#bip-templatehash.md)
*Pushes a hash of specific transaction fields to the stack*

- Useful to represent outcomes or terminal states

#### 4. **OP_CHECKCONTRACTVERIFY** (State-carrying UTXOs) [BIP 443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki)
*Verifies that transaction satisfies a contract specified on the stack*

- On-chain multi-party protocols
- Multi-step transactions; reactive security
- Settlement protocols for L2s/bridges

#### 5. **OP_AMOUNT** (Amount introspection)
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
| **Script Army Knife** | Medium | High | BIPs (347/348/443/#1974/??) |
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

1. **EncodeSakeScript**: Converts emulated scripts to native Bitcoin scripts
1. **WitnessCarrier**: Converts witnesses to an `op_return` `TxOut`
2. **validate_and_sign()**: Validates transactions and produces signatures at oracle side.

### For Users

```rust
use sake::{EncodeSakeScript, SakeWitnessCarrier};

use bitcoin_script::{define_pushable, script};
define_pushable!();

// Create emulated script
let emulated_script = script! { /* your logic */ };

// Encode into native taproot script
let taproot_script = script! {
    // CSV or CTLV opcodes go first, as they can't be enforced in the emulator
    100 OP_CSV OP_DROP  
    <emulated_script.encode_sake_script(&[oracle_pk], 1).unwrap()>
};

// Add witness carrier to transaction
let witness_carrier = TxOut::sake_witness_carrier(&[
    (
        0, // Input index 
        vec![], // Witness stack (elements except for script, control block or annex)
    )
]);
tx.output.push(witness_carrier);
```

### For Oracles

```rust
use sake::validate_and_sign;

// Validate and sign if emulation succeeds
let signature = sake::validate_and_sign(
    keypair,
    // Receives the following
    &tx,
    &prevouts,
    &inputs  // &[(input_index, stack)]
)?;
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
    // Native opcodes (CSV, CTLV) must come before emulated script
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
spending_tx.output.push(
    TxOut::sake_witness_carrier(&[(0, emulation_witness)])
);

// Step 5: Send to oracles for validation
// Oracles run: sake::validate_and_sign(keypair, &spending_tx, &prevouts, &[(0, taproot_script)])
// They return signatures if validation passes

// Step 6: Construct final witness with oracle signatures
let taproot_witness = Witness::from_slice(&[
    oracle_2_signature.to_vec(),  // Second signature (threshold met)
    oracle_1_signature.to_vec(),  // First signature 

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

Where `<data>` is:
```
"SAKE" (4 bytes)
| VERSION (1 byte)  
| INPUT_INDEX (VarInt) - which input this witness is for
| NUM_ELEMENTS (VarInt) - how many stack elements
| [ELEMENT_LENGTH (VarInt) | ELEMENT_DATA (bytes)]...
```

This encodes witness stacks as: `Vec<(usize, Vec<Vec<u8>>)>` where:
- `usize` = input index
- `Vec<Vec<u8>>` = stack elements for that input

**Important**: The witness carrier is added after generating the transaction but removed before validation. It does NOT affect `OP_TEMPLATEHASH` or signature validation—only the oracle signatures cover it.

## Oracle Validation

### Oracle Responsibilities

1. Parse the witness carrier from the last output
2. Extract the encoded SAKE script from the spending input
3. Run the emulation engine with the witness stack
4. If emulation succeeds, sign the transaction
5. Return the signature to the user

### Oracle Independence

- **No coordination**: Oracles don't communicate with each other
- **No state**: Each validation is independent, no blockchain queries needed
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
        <52560> OP_CSV  // ~1 year
        /* .. */
    },
    script! {
        // Normal withdrawal: requires 7-day delay + template
        <1008> OP_CSV  // ~7 days

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

## Limitations

SAKE operates within specific constraints to maintain compatibility and security:

### Technical Constraints

- **Taproot only**: Only works with P2TR outputs
- **Minimal encoding**: All script instructions must be minimally encoded
- **No Annex**: The Annex field in Taproot witnesses is not allowed
- **No OP_CODESEPARATOR**: Disabled (becomes a NOP)

### Emulation Behavior

- **OP_CSV and OP_CTLV are NOPs**: Must be placed before the emulated script in native script
- **OP_SUCCESSx → FAIL**: `OP_SUCCESSx` opcodes cause failure instead of success
- **Pre-carrier introspection**: Signature and introspection opcodes operate on the transaction *before* adding the witness carrier

## Trust Model

### Non-Custodial

Oracles are **not custodians**:
- They are not involved in the locking of funds to scripts that require their signatures
- They cannot steal funds locked to their keys until they are informed about it
- They cannot prevent alternative spending paths
- They can only refuse to sign (liveness failure)
- Users can add fallback conditions for oracle failures

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

**Q: Why is the witness carrier always the last output?**  
A: This is a convention that simplifies parsing and ensures the carrier doesn't interfere with covenant logic that might count or introspect outputs.

**Q: Can I use OP_CSV and OP_CTLV in SAKE scripts?**  
A: These opcodes must be placed in the native script *before* the encoded SAKE script, as they are NOPs in the emulator and need to be enforced by Bitcoin consensus.

**Q: Why doesn't the witness carrier affect OP_TEMPLATEHASH?**  
A: The carrier is removed before emulation to ensure introspection and signature opcodes operate on the "real" transaction that will be broadcast to Bitcoin (minus the carrier).

**Q: Can I nest SAKE scripts?**  
A: No. Each SAKE script is validated independently by oracles. However, you can create complex covenants by chaining transactions with different SAKE scripts.

**Q: What's the maximum size of an emulated script?**  
A: Limited by Bitcoin's Taproot script size limits and the push size limits for the encoded SAKE script. In practice, quite large scripts are possible (similar to native Taproot).

**Q: Can SAKE scripts access the blockchain state?**  
A: No. SAKE scripts operate only on transaction data (inputs, outputs, witness data). They cannot query UTXOs, block headers, or other blockchain state, nor can they enforce CSV or CTLV.

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

**Q How does SAKE compare to confidential-script?**

Similar to the previously discussed confidential-script, [Blind-vault](https://github.com/halseth/blind-vault) aims for privacy instead of observability, further more the blind signer is verifying general purpose program (compile to RiscV) as opposed to Bitcoin Script.

### Security Questions

**Q: What if all my oracles disappear?**  
A: Include alternative tapleafs with time-locked recovery paths or fallback to different oracle sets. Never lock funds without a recovery mechanism.

**Q: Can an oracle front-run my transaction?**  
A: Oracles see your transaction before signing, and they can see the control block after the transaction is broadcasted, so theoretically yes they can spend that same leaf script again if the taproot address is reused. 
Use multiple independent oracles and threshold signatures to reduce this risk. 
Consider using **TEE**-based oracles, and or oracles that have slash-able bonds on other networks.

## Acknowledgments

This implementation is heavily based on [Steven Roose's BitVM/rust-bitcoin-scriptexec](https://github.com/BitVM/rust-bitcoin-scriptexec).
The Script Army Knife proposal is by [Salvatore Ingala](https://salvatoshi.com/).
