use bitcoin::{
    blockdata::script, sighash::TaprootError, taproot::TaprootError as TaprootControlBlockError,
};

use crate::{OpAmountError, exec::Stack, script_encoding, witness_carrier::WitnessCarrierError};

/// Error of a script execution.
///
/// Equivalent to Bitcoin Core's `ScriptError_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    DisabledOpcode,
    BadOpcode,
    PushSize,
    MinimalData,
    InvalidStackOperation,
    UnbalancedConditional,
    TapscriptMinimalIf,
    Verify,
    OpReturn,
    EqualVerify,
    NumEqualVerify,
    CheckSigVerify,
    TapscriptValidationWeight,
    PubkeyType,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TapscriptCheckMultiSig,
    StackSize,

    // new ones for us
    ScriptIntNumericOverflow,
    Debug,

    NoMoreInstructions {
        success: bool,
    },

    OpAmountError(OpAmountError),

    // OP_CHECKCONTRACTVERIFY (BIP-443) errors
    InvalidCCVIndex,
    InvalidCCVTaptree,
    InvalidCCVPubkey,
    MissingCurrentInputSpendInfo,
    CCVScriptMismatch,
    CCVAmountConflict,
    CCVInsufficientAmount,

    /// The taproot signature hash could not be computed (for example because
    /// the prevouts do not match the transaction inputs).
    Sighash(TaprootError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Execution of a SAKE script failed.
    Exec(ExecError),
    /// A script failed to parse or was malformed.
    InvalidScript(script::Error),

    /// The last output does not follow the expected SAKE witness OP_RETURN format.
    InvalidWitnessCarriers(WitnessCarrierError),

    /// Invalid encoding of SAKE script in tapscript with push bytes
    InvalidScriptEncoding(script_encoding::ScriptDecodingError),

    /// Invalid Taproot witness program
    ScriptVerificationFailed { input: usize, final_stack: Stack },

    /// Error signing inputs
    SigningError(TaprootError),

    /// No Inputs to validate
    NoInputs,

    /// Number of prevouts does not match the number of transaction inputs.
    PrevoutsCountMismatch { expected: usize, found: usize },
    /// An input index is out of bounds for the transaction.
    InvalidInputIndex { input: usize, count: usize },
    /// The taproot script/control block witness is missing or too short.
    InvalidWitness { input: usize },
    /// Taproot annex is not supported by SAKE.
    AnnexNotSupported { input: usize },
    /// Only tapscript (0xc0) leaf version is supported.
    UnsupportedLeafVersion { input: usize },
    /// The control block could not be decoded.
    ControlBlock(TaprootControlBlockError),
    /// The control block does not commit to the supplied script for this prevout.
    ControlBlockMismatch { input: usize },
    /// The spent output is not P2TR.
    NotP2trPrevout { input: usize },
    /// No witness stack was supplied in the carrier for a SAKE input.
    MissingSakeWitness { input: usize },
    /// The carrier contains more than one stack for the same input.
    DuplicateSakeWitness { input: usize },
    /// The carrier contains a stack for an input that is not a SAKE input.
    UnexpectedSakeWitness { input: usize },
}
