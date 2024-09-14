use frost_core::{Ciphersuite, Error as FrostError};
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(not(feature = "std"))]
use thiserror_nostd_notrait::Error;

/// This type represents all possible errors for which a signer can be marked as
/// malicious.
#[derive(Error, Debug, Clone)]
pub enum MaliciousSignerError {
    /// Signer unsolicitedly replied to coordinator.
    #[error("Unsolicited reply")]
    UnsolicitedReply,
    /// Signature share is missing or its verification has failed.
    #[error("Invalid signature share")]
    InvalidSignatureShare,
}

/// This type represents all possible errors that can occur in ROAST protocol.
#[derive(Error, Debug)]
pub enum Error<C: Ciphersuite> {
    /// Error in FROST protocol.
    #[error("FROST error: {0}")]
    Frost(#[from] FrostError<C>),
    /// Malicious signer.
    #[error("Malicious signer: {0}")]
    MaliciousSigner(#[from] MaliciousSignerError),
    /// Too many malicious signers.
    #[error("Too many malicious signers")]
    TooManyMaliciousSigners,
}
