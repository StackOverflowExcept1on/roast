#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

#[cfg_attr(any(test, feature = "test-impl"), macro_use)]
extern crate alloc;

mod coordinator;
mod error;
mod signer;

#[cfg(any(test, feature = "test-impl"))]
pub mod tests;

pub use frost_core as frost;

pub use coordinator::*;
pub use error::*;
pub use signer::*;
