#![no_std]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

mod coordinator {
    /// Represents all possible session statuses.
    pub type SessionStatus = roast_core::SessionStatus<frost_ristretto255::Ristretto255Sha512>;

    /// Represents coordinator.
    pub type Coordinator = roast_core::Coordinator<frost_ristretto255::Ristretto255Sha512>;
}

pub mod dkg {
    //! Distributed Key Generation types.

    pub use roast_core::dkg::DkgStatus;

    /// Represents dealer that can be used for Distributed Key Generation.
    pub type Dealer = roast_core::dkg::Dealer<frost_ristretto255::Ristretto255Sha512, sha2::Sha512>;

    /// Represents participant of Distributed Key Generation.
    pub type Participant =
        roast_core::dkg::Participant<frost_ristretto255::Ristretto255Sha512, sha2::Sha512>;
}

pub mod error {
    //! Error types.

    /// Represents all possible errors that can occur in FROST protocol.
    pub type FrostError = frost_ristretto255::Error;

    /// Represents all possible errors that can occur in Distributed Key
    /// Generation protocol on dealer side.
    pub type DkgDealerError =
        roast_core::error::DkgDealerError<frost_ristretto255::Ristretto255Sha512>;

    /// Represents all possible errors that can occur in Distributed Key
    /// Generation protocol on participant side.
    pub type DkgParticipantError =
        roast_core::error::DkgParticipantError<frost_ristretto255::Ristretto255Sha512>;

    pub use roast_core::error::MaliciousSignerError;

    /// Represents all possible errors that can occur in ROAST protocol.
    pub type RoastError = roast_core::error::RoastError<frost_ristretto255::Ristretto255Sha512>;
}

mod signer {
    /// Represents signer.
    pub type Signer = roast_core::Signer<frost_ristretto255::Ristretto255Sha512>;
}

pub use frost_ristretto255 as frost;

pub use coordinator::*;
pub use signer::*;
