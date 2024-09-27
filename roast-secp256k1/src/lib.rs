#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

mod coordinator {
    /// Represents all possible session statuses.
    pub type SessionStatus = roast_core::SessionStatus<frost_secp256k1::Secp256K1Sha256>;

    /// Represents coordinator.
    pub type Coordinator = roast_core::Coordinator<frost_secp256k1::Secp256K1Sha256>;
}

pub mod dkg {
    //! Distributed Key Generation types.

    /// Represents all possible Distributed Key Generation statuses.
    pub type DistributedKeyGenerationStatus =
        roast_core::dkg::DistributedKeyGenerationStatus<frost_secp256k1::Secp256K1Sha256>;

    /// Represents trusted third party that can be used for Distributed Key
    /// Generation.
    pub type TrustedThirdParty =
        roast_core::dkg::TrustedThirdParty<frost_secp256k1::Secp256K1Sha256>;

    /// Represents participant of Distributed Key Generation.
    pub type Participant = roast_core::dkg::Participant<frost_secp256k1::Secp256K1Sha256>;
}

pub mod error {
    //! Error types.

    /// Represents all possible errors that can occur in FROST protocol.
    pub type FrostError = roast_core::error::FrostError<frost_secp256k1::Secp256K1Sha256>;

    pub use roast_core::error::{MaliciousSignerError, RoastError};

    /// Represents all possible errors that can occur.
    pub type Error = roast_core::error::Error<frost_secp256k1::Secp256K1Sha256>;
}

mod signer {
    /// Represents signer.
    pub type Signer = roast_core::Signer<frost_secp256k1::Secp256K1Sha256>;
}

pub use frost_secp256k1 as frost;

pub use coordinator::*;
pub use signer::*;
