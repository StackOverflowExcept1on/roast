//! Error types.

use frost_core::{Ciphersuite, Error as FrostErrorType};
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(not(feature = "std"))]
use thiserror_nostd_notrait::Error;

/// Represents all possible errors that can occur in FROST protocol.
pub type FrostError<C> = FrostErrorType<C>;

/// Represents all possible errors that can occur in Distributed Key Generation
/// protocol on dealer side.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum DkgDealerError<C: Ciphersuite> {
    /// Error in FROST protocol.
    #[error("FROST error: {0}")]
    Frost(#[from] FrostError<C>),
    /// Duplicate participants.
    #[error("Duplicate participants")]
    DuplicateParticipants,
    /// Unknown participant.
    #[error("Unknown participant")]
    UnknownParticipant,
    /// Invalid package length.
    #[error("Invalid package length")]
    InvalidPackageLength,
    /// Invalid temporary secret key.
    #[error("Invalid temporary secret key")]
    InvalidTempSecretKey,
    /// Invalid secret shares.
    #[error("Invalid secret shares")]
    InvalidSecretShares,
    /// Invalid state transition.
    #[error("Invalid state transition")]
    InvalidStateTransition,
}

/// Represents all possible errors that can occur in Distributed Key Generation
/// protocol on participant side.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum DkgParticipantError<C: Ciphersuite> {
    /// Error in FROST protocol.
    #[error("FROST error: {0}")]
    Frost(#[from] FrostError<C>),
    /// Invalid state transition.
    #[error("Invalid state transition")]
    InvalidStateTransition,
    /// Encryption error.
    #[error("Encryption error")]
    Encryption,
    /// Invalid secret shares.
    #[error("Invalid secret shares")]
    InvalidSecretShares,
}

/// Represents all possible errors that can occur in Distributed Key Generation
/// protocol.
#[cfg(any(test, feature = "test-impl"))]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum DkgError<C: Ciphersuite> {
    /// Error in Distributed Key Generation protocol on dealer side.
    #[error("DKG dealer error: {0}")]
    DkgDealer(#[from] DkgDealerError<C>),
    /// Error in Distributed Key Generation protocol on participant side.
    #[error("DKG participant error: {0}")]
    DkgParticipant(#[from] DkgParticipantError<C>),
}

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
pub enum RoastError<C: Ciphersuite> {
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
