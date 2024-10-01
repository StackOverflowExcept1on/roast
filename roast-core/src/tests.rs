//! Test cases.

use crate::error::DkgError;
use crate::{
    dkg::{Dealer, Participant},
    error::{Error, RoastError},
    frost::{
        keys::{self, IdentifierList, KeyPackage},
        Ciphersuite,
    },
    Coordinator, SessionStatus, Signer,
};
use alloc::collections::BTreeMap;
use frost_core::{round2::SignatureShare, Field, Group};
use rand::{seq::SliceRandom, CryptoRng, RngCore};

/// Runs DKG algorithm with `min_signers`/`max_signers` and no malicious
/// participants.
pub fn test_dkg_basic<C: Ciphersuite, RNG: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    rng: &mut RNG,
) -> Result<(), Error<C>> {
    let mut identifiers = vec![];
    let mut participants = vec![];

    for participant_index in 1..=max_signers {
        let identifier = participant_index.try_into().expect("should be nonzero");
        identifiers.push(identifier);
        let participant = Participant::new(identifier, max_signers, min_signers, rng)?;
        participants.push(participant);
    }

    let mut dealer = Dealer::new(max_signers, min_signers, identifiers)?;

    for participant in participants.iter_mut() {
        dealer.receive_round1_package(participant.identifier(), participant.round1_package()?)?;
    }

    assert!(dealer.blame_round1_participants().next().is_none());

    for participant in participants.iter_mut() {
        let round2_packages =
            participant.receive_round1_packages(dealer.round1_packages().clone())?;
        dealer.receive_round2_packages(participant.identifier(), round2_packages)?;
    }

    assert!(dealer.blame_round2_participants().next().is_none());

    for participant in participants.iter_mut() {
        if let Some(round2_packages) = dealer.round2_packages(participant.identifier()).cloned() {
            match participant.receive_round2_packages(round2_packages) {
                Ok((_key_package, public_key_package)) => {
                    assert_eq!(public_key_package, dealer.public_key_package()?);
                }
                Err(err) => {
                    if let Error::Dkg(DkgError::InvalidSecretShares) = err {
                        dealer.receive_round2_culprits(
                            participant.identifier(),
                            participant.round2_culprits()?,
                        )?;
                    }
                }
            }
        }
    }

    dealer.try_finish()?;

    Ok(())
}

/// Runs ROAST algorithm with `min_signers`/`max_signers` multi-signature and no
/// malicious signers.
pub fn test_basic<C: Ciphersuite, RNG: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    rng: &mut RNG,
) -> Result<(), Error<C>> {
    test_malicious(min_signers, max_signers, 0, rng)
}

/// Runs ROAST algorithm with `min_signers`/`max_signers` multi-signature and
/// `malicious_signers`.
pub fn test_malicious<C: Ciphersuite, RNG: RngCore + CryptoRng>(
    min_signers: u16,
    max_signers: u16,
    malicious_signers: u16,
    rng: &mut RNG,
) -> Result<(), Error<C>> {
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

    assert!(malicious_signers <= max_signers - min_signers);

    let mut malicious_mask = vec![true; malicious_signers as usize];
    malicious_mask.resize(max_signers as usize, false);
    malicious_mask.shuffle(rng);

    let mut signing_packages: BTreeMap<_, _> = BTreeMap::new();
    let mut session_counter = 0;

    'outer: loop {
        'inner: for (index, is_malicious) in (1..=max_signers).zip(malicious_mask.iter().copied()) {
            let identifier = index.try_into()?;
            let signer = signers.get_mut(&identifier).unwrap();
            let signature_share = signing_packages
                .get(&identifier)
                .and_then(|signing_package| {
                    if is_malicious {
                        let zero = <<C::Group as Group>::Field as Field>::zero();
                        let serialization = <<C::Group as Group>::Field as Field>::serialize(&zero);
                        signer.regenerate_signing_nonces(rng);
                        Some(SignatureShare::<C>::deserialize(serialization.as_ref()).unwrap())
                    } else {
                        signer.receive(signing_package, rng).ok()
                    }
                });
            match coordinator.receive(identifier, signature_share, signer.signing_commitments()) {
                Ok(session_status) => match session_status {
                    SessionStatus::InProgress => continue 'inner,
                    SessionStatus::Started {
                        signers,
                        signing_package,
                    } => {
                        session_counter += 1;
                        for signer in signers {
                            signing_packages.insert(signer, signing_package.clone());
                        }
                    }
                    SessionStatus::Finished { .. } => break 'outer,
                },
                Err(Error::Roast(RoastError::MaliciousSigner(_))) => continue 'inner,
                Err(Error::Roast(RoastError::TooManyMaliciousSigners)) => unreachable!(),
                Err(Error::Dkg(_)) => unimplemented!(),
                Err(Error::Frost(err)) => return Err(err)?,
            }
        }
    }

    assert!(session_counter <= max_signers - min_signers + 1);

    Ok(())
}
