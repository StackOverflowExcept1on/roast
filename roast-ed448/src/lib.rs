// TODO: #![cfg_attr(not(feature = "std"), no_std)] (https://github.com/ZcashFoundation/frost/issues/769)
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

mod coordinator {
    /// Represents all possible session statuses.
    pub type SessionStatus = roast_core::SessionStatus<frost_ed448::Ed448Shake256>;

    /// Represents coordinator.
    pub type Coordinator = roast_core::Coordinator<frost_ed448::Ed448Shake256>;
}

// TODO: replace `sha3::Shake256` with something else to support dkg

pub mod error {
    //! Error types.

    /// Represents all possible errors that can occur in FROST protocol.
    pub type FrostError = frost_ed448::Error;

    /// Represents all possible errors that can occur in Distributed Key
    /// Generation protocol on dealer side.
    pub type DkgDealerError = roast_core::error::DkgDealerError<frost_ed448::Ed448Shake256>;

    /// Represents all possible errors that can occur in Distributed Key
    /// Generation protocol on participant side.
    pub type DkgParticipantError =
        roast_core::error::DkgParticipantError<frost_ed448::Ed448Shake256>;

    pub use roast_core::error::MaliciousSignerError;

    /// Represents all possible errors that can occur in ROAST protocol.
    pub type RoastError = roast_core::error::RoastError<frost_ed448::Ed448Shake256>;
}

mod signer {
    /// Represents signer.
    pub type Signer = roast_core::Signer<frost_ed448::Ed448Shake256>;
}

pub use frost_ed448 as frost;

pub use coordinator::*;
pub use signer::*;
