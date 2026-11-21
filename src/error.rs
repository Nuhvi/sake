use bitcoin::{
    blockdata::script, sighash::TaprootError, taproot::TaprootError as TaprootControlBlockError,
};

use crate::{OpAmountError, script_encoding, stack::Stack, witness_carrier::WitnessCarrierError};

/// Error of a script execution.
///
/// Equivalent to Bitcoin Core's `ScriptError_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The script used a disabled opcode.
    DisabledOpcode,
    /// The opcode is unknown, or it is not valid in tapscript.
    BadOpcode,
    /// A push or a stack element is larger than 520 bytes.
    PushSize,
    /// A script number is not minimally encoded.
    MinimalData,
    /// The stack holds too few elements for the opcode.
    InvalidStackOperation,
    /// An `OP_IF` or `OP_NOTIF` has no matching `OP_ENDIF`.
    UnbalancedConditional,
    /// The argument of `OP_IF` or `OP_NOTIF` is not empty and is not `0x01`.
    TapscriptMinimalIf,
    /// `OP_VERIFY` consumed a false value.
    Verify,
    /// The script executed `OP_RETURN`.
    OpReturn,
    /// `OP_EQUALVERIFY` compared unequal values.
    EqualVerify,
    /// `OP_NUMEQUALVERIFY` compared unequal numbers.
    NumEqualVerify,
    /// `OP_CHECKSIGVERIFY` failed.
    CheckSigVerify,
    /// The tapscript validation weight budget is exhausted.
    TapscriptValidationWeight,
    /// The public key is empty or invalid.
    PubkeyType,
    /// The Schnorr signature has an invalid size.
    SchnorrSigSize,
    /// The Schnorr signature has a sighash type other than `SIGHASH_DEFAULT`.
    SchnorrSigHashtype,
    /// The Schnorr signature is invalid.
    SchnorrSig,
    /// The script used `OP_CHECKMULTISIG`, which tapscript forbids.
    TapscriptCheckMultiSig,
    /// The stack and the altstack hold more than 1000 elements.
    StackSize,

    // new ones for us
    /// A script number does not fit in four bytes.
    ScriptIntNumericOverflow,
    /// The script used `OP_RESERVED`.
    Debug,
    /// The script could not be parsed during execution.
    ///
    /// `Exec::new` rejects this case before execution starts. The variant keeps
    /// the interpreter total if that check changes.
    InvalidScript(script::Error),

    /// The script ended.
    NoMoreInstructions {
        /// True when the final stack holds exactly one true value.
        success: bool,
    },

    /// `OP_AMOUNT` failed.
    OpAmountError(OpAmountError),

    // OP_CHECKCONTRACTVERIFY (BIP-443) errors
    /// The `OP_CHECKCONTRACTVERIFY` index is out of range.
    InvalidCCVIndex,
    /// The `OP_CHECKCONTRACTVERIFY` taptree is not a 32-byte hash.
    InvalidCCVTaptree,
    /// The `OP_CHECKCONTRACTVERIFY` public key is invalid.
    InvalidCCVPubkey,
    /// `OP_CHECKCONTRACTVERIFY` used `-1`, but the input has no spend info.
    MissingCurrentInputSpendInfo,
    /// The target input or output does not match the computed P2TR output.
    CCVScriptMismatch,
    /// Two `OP_CHECKCONTRACTVERIFY` checks on one output use conflicting amount modes.
    CCVAmountConflict,
    /// The input amount is smaller than the checked output amount.
    CCVInsufficientAmount,

    /// The taproot signature hash could not be computed (for example because
    /// the prevouts do not match the transaction inputs).
    Sighash(TaprootError),
}

/// Error from the SAKE validation API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Execution of a SAKE script failed.
    Exec(ExecError),
    /// A script failed to parse or was malformed.
    InvalidScript(script::Error),

    /// The last output does not follow the expected SAKE witness OP_RETURN format.
    InvalidWitnessCarriers(WitnessCarrierError),

    /// The tapscript SAKE encoding is invalid.
    InvalidScriptEncoding(script_encoding::ScriptDecodingError),

    /// A SAKE script did not succeed.
    ScriptVerificationFailed {
        /// Index of the input in the transaction.
        input: usize,
        /// Stack after the script stopped.
        final_stack: Stack,
    },

    /// The taproot signature hash for signing could not be computed.
    SigningError(TaprootError),

    /// The `inputs` slice is empty.
    NoInputs,

    /// Number of prevouts does not match the number of transaction inputs.
    PrevoutsCountMismatch {
        /// Number of transaction inputs.
        expected: usize,
        /// Number of supplied prevouts.
        found: usize,
    },
    /// An input index is out of bounds for the transaction.
    InvalidInputIndex {
        /// The invalid input index.
        input: usize,
        /// Number of transaction inputs.
        count: usize,
    },
    /// The taproot script/control block witness is missing or too short.
    InvalidWitness {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// Taproot annex is not supported by SAKE.
    AnnexNotSupported {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// Only tapscript (0xc0) leaf version is supported.
    UnsupportedLeafVersion {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// The control block could not be decoded.
    ControlBlock(TaprootControlBlockError),
    /// The control block does not commit to the supplied script for this prevout.
    ControlBlockMismatch {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// The spent output is not P2TR.
    NotP2trPrevout {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// No witness stack was supplied in the carrier for a SAKE input.
    MissingSakeWitness {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// The carrier contains more than one stack for the same input.
    DuplicateSakeWitness {
        /// Index of the input in the transaction.
        input: usize,
    },
    /// The carrier contains a stack for an input that is not a SAKE input.
    UnexpectedSakeWitness {
        /// Index of the input in the transaction.
        input: usize,
    },
}
