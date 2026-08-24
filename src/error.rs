use std::fmt;

/// Every failure mode a caller of this crate can hit. Nothing in this crate
/// panics on malformed or hostile input, the error path is always this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VeilproofError {
    /// A group element was outside [1, p) or not in the order-q subgroup.
    InvalidElement(String),
    /// A scalar was outside [0, q).
    InvalidScalar(String),
    /// A proof failed a structural check (wrong shape, wrong length, or the
    /// verification equation did not hold).
    InvalidProof(String),
    /// Bytes handed to a deserializer did not decode into the expected shape.
    Deserialization(String),
    /// A requested range width is larger than this teaching-grade
    /// implementation supports.
    RangeTooLarge(String),
    /// The witness supplied to a prover did not satisfy the statement it was
    /// asked to prove (for example a value outside the claimed range).
    InvalidWitness(String),
    /// The operating-system entropy source could not be read. Returned
    /// instead of panicking so a consumer of this library is never crashed
    /// out from under by a failed randomness read.
    Entropy(String),
}

impl fmt::Display for VeilproofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VeilproofError::InvalidElement(msg) => write!(f, "invalid group element: {msg}"),
            VeilproofError::InvalidScalar(msg) => write!(f, "invalid scalar: {msg}"),
            VeilproofError::InvalidProof(msg) => write!(f, "invalid proof: {msg}"),
            VeilproofError::Deserialization(msg) => write!(f, "deserialization failed: {msg}"),
            VeilproofError::RangeTooLarge(msg) => write!(f, "range too large: {msg}"),
            VeilproofError::InvalidWitness(msg) => write!(f, "invalid witness: {msg}"),
            VeilproofError::Entropy(msg) => write!(f, "entropy source failure: {msg}"),
        }
    }
}

impl std::error::Error for VeilproofError {}
