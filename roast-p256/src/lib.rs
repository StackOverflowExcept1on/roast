#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

mod coordinator {
    /// Represents all possible session statuses.
    pub type SessionStatus = roast_core::SessionStatus<frost_p256::P256Sha256>;

    /// Represents coordinator.
    pub type Coordinator = roast_core::Coordinator<frost_p256::P256Sha256>;
}

mod error {
    pub use roast_core::MaliciousSignerError;

    /// Represents all possible errors that can occur.
    pub type Error = roast_core::Error<frost_p256::P256Sha256>;
}

mod signer {
    /// Represents signer.
    pub type Signer = roast_core::Signer<frost_p256::P256Sha256>;
}

pub use frost_p256 as frost;

pub use coordinator::*;
pub use error::*;
pub use signer::*;
