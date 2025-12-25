use bitcoin::{blockdata::script, sighash::TaprootError};

use crate::exec::Stack;

/// Error of a script execution.
///
/// Equivalent to Bitcoin Core's `ScriptError_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    DisabledOpcode,
    OpCodeseparator,
    BadOpcode,
    OpCount,
    PushSize,
    MinimalData,
    InvalidStackOperation,
    NegativeLocktime,
    UnsatisfiedLocktime,
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
    PubkeyCount,
    StackSize,
    WitnessPubkeyType,

    // new ones for us
    ScriptIntNumericOverflow,
    Debug,

    TxHashVerify,
    TxHash(&'static str),

    NoMoreInstructions { success: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessCarrierError {
    NotOpReturn,
    MissingPrefix,
    WrongVersion,
    InvalidStacksCount,
    InvalidInputIndex,
    InvalidElementsCount,
    InvalidElement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Execution of a SAKE script failed.
    Exec(ExecError),
    /// A script failed to parse or was malformed.
    InvalidScript(script::Error),

    /// Number of witness stacks does not match number of SAKE inputs.
    WitnessCountMismatch { expected: usize, found: usize },
    /// Provided scripts don't have the same input indexes as in the witness carrier
    WitnessIndexesMismatch { expected: usize, found: usize },
    /// The last output does not follow the expected SAKE witness OP_RETURN format.
    InvalidWitnessCarriers(WitnessCarrierError),
    /// A witness stack was encoded in an invalid or corrupt format.
    InvalidWitnessEncoding,

    /// Invalid Taproot witness program
    ScriptVerificationFailed { input: usize, final_stack: Stack },

    /// Error signing inputs
    SigningError(TaprootError),

    /// No Inputs to validate
    NoInputs,
}
