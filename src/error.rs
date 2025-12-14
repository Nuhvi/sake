use bitcoin::blockdata::script;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Execution of a SAKE script failed.
    Exec(ExecError),
    /// A script failed to parse or was malformed.
    InvalidScript(script::Error),

    /// Transaction has no SAKE locked inputs.
    NoRelevantInputsToValidate,

    /// Number of witness stacks does not match number of SAKE inputs.
    WitnessCountMismatch { expected: usize, found: usize },
    /// The last output does not follow the expected SAKE witness OP_RETURN format.
    InvalidWitnessOutputFormat,
    /// A witness stack was encoded in an invalid or corrupt format.
    InvalidWitnessEncoding,
}
