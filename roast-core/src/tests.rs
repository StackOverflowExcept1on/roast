//! Test cases.

use crate::{
    frost::{
        keys::{self, IdentifierList, KeyPackage},
        Ciphersuite,
    },
    Coordinator, Error, SessionStatus, Signer,
};
use alloc::collections::BTreeMap;
use rand_core::{CryptoRng, RngCore};

/// Runs ROAST algorithm with 2/3 multi-signature.
pub fn test_basic<C: Ciphersuite, RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Result<(), Error<C>> {
    let max_signers = 3;
    let min_signers = 2;
    let (secret_shares, public_key_package) =
        keys::generate_with_dealer(max_signers, min_signers, IdentifierList::Default, rng)?;

    let mut coordinator = Coordinator::new(
        max_signers,
        min_signers,
        public_key_package,
        b"message to sign".into(),
    )?;
    let mut signers: BTreeMap<_, _> = BTreeMap::new();

    for (identifier, secret_share) in secret_shares {
        let key_package = KeyPackage::try_from(secret_share)?;
        signers.insert(identifier, Signer::new(key_package, rng));
    }

    let mut session_statuses1 = Vec::new();
    for index in 1..=min_signers {
        let identifier = index.try_into()?;
        let signer = signers.get(&identifier).unwrap();
        let response = coordinator.receive(identifier, None, signer.signing_commitments())?;
        session_statuses1.push(response);
    }

    assert_eq!(session_statuses1.len(), min_signers as usize);
    assert!(matches!(
        session_statuses1.last(),
        Some(SessionStatus::Started { .. })
    ));

    let mut session_statuses2 = Vec::new();
    if let Some(SessionStatus::Started {
        signing_package, ..
    }) = session_statuses1.last()
    {
        for index in 1..=min_signers {
            let identifier = index.try_into()?;
            let signer = signers.get_mut(&identifier).unwrap();
            let signature_share = signer.receive(signing_package, rng)?;
            let response = coordinator.receive(
                identifier,
                Some(signature_share),
                signer.signing_commitments(),
            )?;
            session_statuses2.push(response);
        }
    }

    assert_eq!(session_statuses2.len(), min_signers as usize);
    assert!(matches!(
        session_statuses2.last(),
        Some(SessionStatus::Finished { .. })
    ));

    Ok(())
}
