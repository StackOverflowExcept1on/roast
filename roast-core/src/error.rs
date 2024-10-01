//! Error types.

use frost_core::Ciphersuite;
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(not(feature = "std"))]
use thiserror_nostd_notrait::Error;

/// Represents all possible errors that can occur in FROST protocol.
pub type FrostError<C> = frost_core::Error<C>;

/// Represents all possible errors for which signer can be marked as malicious.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MaliciousSignerError {
    /// Signer unsolicitedly replied to coordinator.
    #[error("Unsolicited reply")]
    UnsolicitedReply,
    /// Signature share is missing or its verification has failed.
    #[error("Invalid signature share")]
    InvalidSignatureShare,
}

/// Represents all possible errors that can occur in ROAST protocol.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum RoastError {
    /// Malicious signer.
    #[error("Malicious signer: {0}")]
    MaliciousSigner(#[from] MaliciousSignerError),
    /// Too many malicious signers.
    #[error("Too many malicious signers")]
    TooManyMaliciousSigners,
}

/// Represents all possible errors that can occur in Distributed Key Generation.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum DkgError {
    /// Duplicate participants.
    #[error("Duplicate participants")]
    DuplicateParticipants,
    /// Unknown participant.
    #[error("Unknown participant")]
    UnknownParticipant,
    /// Invalid secret shares.
    #[error("Invalid secret shares")]
    InvalidSecretShares,
}

/// Represents all possible errors that can occur.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error<C: Ciphersuite> {
    /// Error in FROST protocol.
    #[error("FROST error: {0}")]
    Frost(#[from] FrostError<C>),
    /// Error in Distributed Key Generation.
    #[error("DKG error: {0}")]
    Dkg(#[from] DkgError),
    /// Error in ROAST protocol.
    #[error("ROAST error: {0}")]
    Roast(#[from] RoastError),
}
