#![cfg_attr(not(feature = "std"), no_std)]
// TODO #![deny(missing_docs)]

extern crate alloc;

mod coordinator;
mod error;
mod signer;

pub use frost_secp256k1 as frost;

pub use coordinator::*;
pub use error::*;
pub use signer::*;
