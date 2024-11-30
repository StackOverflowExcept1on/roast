//! Distributed Key Generation types.

use crate::error::{DkgDealerError, DkgParticipantError, FrostError};
use aes::cipher::{crypto_common::BlockSizeUser, KeyIvInit, StreamCipher};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{iter, marker::PhantomData};
use digest::Digest;
use frost_core::{
    keys::{
        self,
        dkg::{self, round1, round2},
        KeyPackage, PublicKeyPackage, SecretShare, SigningShare,
    },
    Ciphersuite, Field, Group, Identifier, SigningKey, VerifyingKey,
};
use hkdf::{hmac::SimpleHmac, Hkdf};
use rand_core::{CryptoRng, RngCore};

fn diffie_hellman<C: Ciphersuite>(
    secret_key: &SigningKey<C>,
    public_key: &VerifyingKey<C>,
) -> Option<<C::Group as Group>::Serialization> {
    let shared_secret = public_key.to_element() * secret_key.to_scalar();
    let shared_secret_bytes = <C::Group as Group>::serialize(&shared_secret).ok()?;

    Some(shared_secret_bytes)
}

fn hkdf<C: Ciphersuite, H: Clone + BlockSizeUser + Digest>(
    shared_secret_bytes: <C::Group as Group>::Serialization,
) -> Option<([u8; 16], [u8; 16])> {
    const KEY_PREFIX: &[u8] = b"key";
    const IV_PREFIX: &[u8] = b"iv";

    let hkdf = Hkdf::<H, SimpleHmac<H>>::new(Some(C::ID.as_ref()), shared_secret_bytes.as_ref());

    let mut key = [0; 16];
    hkdf.expand(KEY_PREFIX, &mut key).ok()?;

    let mut iv = [0; 16];
    hkdf.expand(IV_PREFIX, &mut iv).ok()?;

    Some((key, iv))
}

fn try_apply_keystream(key: [u8; 16], iv: [u8; 16], buffer: &mut [u8]) -> Option<()> {
    type Aes128Ctr32BE = ctr::Ctr32BE<aes::Aes128>;

    Aes128Ctr32BE::new(&key.into(), &iv.into())
        .try_apply_keystream(buffer)
        .ok()
}

fn encrypt_round2_package<C: Ciphersuite, H: Clone + BlockSizeUser + Digest>(
    round2_package: round2::Package<C>,
    receiver_temp_public_key: &VerifyingKey<C>,
    sender_temp_secret_key: &SigningKey<C>,
) -> Option<Vec<u8>> {
    let shared_secret_bytes = diffie_hellman(sender_temp_secret_key, receiver_temp_public_key)?;
    let (key, iv) = hkdf::<C, H>(shared_secret_bytes)?;

    let signing_share = round2_package.signing_share().to_scalar();
    let singing_share_bytes = <<C::Group as Group>::Field as Field>::serialize(&signing_share);

    let mut buffer = singing_share_bytes.as_ref().to_vec();
    try_apply_keystream(key, iv, &mut buffer)?;

    Some(buffer)
}

fn decrypt_round2_package<C: Ciphersuite, H: Clone + BlockSizeUser + Digest>(
    round2_package_encrypted: Vec<u8>,
    sender_temp_public_key: &VerifyingKey<C>,
    receiver_temp_secret_key: &SigningKey<C>,
) -> Option<round2::Package<C>> {
    let shared_secret_bytes = diffie_hellman(receiver_temp_secret_key, sender_temp_public_key)?;
    let (key, iv) = hkdf::<C, H>(shared_secret_bytes)?;

    let mut buffer = round2_package_encrypted;
    try_apply_keystream(key, iv, &mut buffer)?;

    let buffer_serialized = buffer.try_into().ok()?;
    let signing_share =
        SigningShare::new(<<C::Group as Group>::Field>::deserialize(&buffer_serialized).ok()?);

    Some(round2::Package::new(signing_share))
}

type Round1Package<C> = (round1::Package<C>, VerifyingKey<C>);

/// Represents all possible Distributed Key Generation statuses.
#[derive(Debug)]
pub enum DkgStatus {
    /// Distributed Key Generation still in progress.
    InProgress,
    /// Finished round1 of Distributed Key Generation.
    FinishedRound1,
    /// Finished round2 of Distributed Key Generation.
    FinishedRound2,
    /// Finished round3 of Distributed Key Generation.
    FinishedRound3,
}

/// Represents dealer that can be used for Distributed Key Generation.
#[derive(Debug)]
pub struct Dealer<C: Ciphersuite, H: Clone + BlockSizeUser + Digest> {
    max_signers: u16,
    min_signers: u16,
    participants: Vec<Identifier<C>>,
    participants_set: BTreeSet<Identifier<C>>,
    round1_packages: BTreeMap<Identifier<C>, Round1Package<C>>,
    round2_packages_encrypted: BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, Vec<u8>>>,
    round2_participants_set: BTreeSet<Identifier<C>>,
    round2_culprits_set: BTreeSet<Identifier<C>>,
    phantom: PhantomData<H>,
}

impl<C: Ciphersuite, H: Clone + BlockSizeUser + Digest> Dealer<C, H> {
    /// Creates a new [`Dealer`].
    pub fn new(
        max_signers: u16,
        min_signers: u16,
        participants: Vec<Identifier<C>>,
    ) -> Result<Self, DkgDealerError<C>> {
        keys::validate_num_of_signers(min_signers, max_signers)?;

        let participants_set = BTreeSet::from_iter(participants.clone());
        if participants_set.len() != participants.len() {
            return Err(DkgDealerError::DuplicateParticipants);
        }

        Ok(Self {
            max_signers,
            min_signers,
            participants,
            participants_set,
            round1_packages: BTreeMap::new(),
            round2_packages_encrypted: BTreeMap::new(),
            round2_participants_set: BTreeSet::new(),
            round2_culprits_set: BTreeSet::new(),
            phantom: PhantomData,
        })
    }

    /// Returns the maximum number of signers.
    pub fn max_signers(&self) -> u16 {
        self.max_signers
    }

    /// Returns the minimum number of signers.
    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    /// Returns an iterator of participants.
    pub fn participants(&self) -> impl Iterator<Item = Identifier<C>> + '_ {
        self.participants.iter().copied()
    }

    /// Returns the round1 packages.
    pub fn round1_packages(&self) -> &BTreeMap<Identifier<C>, Round1Package<C>> {
        &self.round1_packages
    }

    /// Returns the round2 packages encrypted by receiver identifier.
    pub fn round2_packages_encrypted(
        &self,
        receiver_identifier: Identifier<C>,
    ) -> Option<&BTreeMap<Identifier<C>, Vec<u8>>> {
        self.round2_packages_encrypted.get(&receiver_identifier)
    }

    /// Receives the [`Identifier`], `round1_package` and `temp_public_key` from
    /// the participant.
    pub fn receive_round1_package(
        &mut self,
        identifier: Identifier<C>,
        (round1_package, temp_public_key): Round1Package<C>,
    ) -> Result<DkgStatus, DkgDealerError<C>> {
        if !self.participants_set.contains(&identifier) {
            return Err(DkgDealerError::UnknownParticipant);
        }

        if round1_package.commitment().coefficients().len() != self.min_signers as usize {
            return Err(DkgDealerError::Frost(
                FrostError::IncorrectNumberOfCommitments,
            ));
        }

        dkg::verify_proof_of_knowledge(
            identifier,
            round1_package.commitment(),
            round1_package.proof_of_knowledge(),
        )?;

        self.round1_packages
            .insert(identifier, (round1_package, temp_public_key));

        if self.round1_packages.len() == self.max_signers as usize {
            return Ok(DkgStatus::FinishedRound1);
        }

        Ok(DkgStatus::InProgress)
    }

    /// Returns an iterator of participants who have not sent their round1
    /// package.
    pub fn blame_round1_participants(&self) -> impl Iterator<Item = Identifier<C>> + '_ {
        self.participants
            .iter()
            .filter(|id| !self.round1_packages.contains_key(id))
            .copied()
    }

    /// Receives the [`Identifier`] and `round2_packages_encrypted` from the
    /// participant.
    pub fn receive_round2_packages(
        &mut self,
        identifier: Identifier<C>,
        round2_packages_encrypted: BTreeMap<Identifier<C>, Vec<u8>>,
    ) -> Result<DkgStatus, DkgDealerError<C>> {
        if !self.participants_set.contains(&identifier) {
            return Err(DkgDealerError::UnknownParticipant);
        }

        if round2_packages_encrypted.len() != (self.max_signers - 1) as usize {
            return Err(DkgDealerError::Frost(FrostError::IncorrectNumberOfPackages));
        }

        if self
            .participants
            .iter()
            .filter(|id| identifier.ne(id))
            .any(|id| !round2_packages_encrypted.contains_key(id))
        {
            return Err(DkgDealerError::Frost(FrostError::IncorrectPackage));
        }

        let zero = <<C::Group as Group>::Field>::zero();
        let serialization = <<C::Group as Group>::Field>::serialize(&zero);
        let expected_len = serialization.as_ref().len();

        if round2_packages_encrypted
            .values()
            .any(|round2_package_encrypted| round2_package_encrypted.len() != expected_len)
        {
            return Err(DkgDealerError::InvalidPackageLength);
        }

        for (receiver_identifier, round2_package_encrypted) in round2_packages_encrypted {
            self.round2_packages_encrypted
                .entry(receiver_identifier)
                .or_default()
                .insert(identifier, round2_package_encrypted);
        }

        self.round2_participants_set.insert(identifier);

        if self.round2_participants_set.len() == self.max_signers as usize {
            return Ok(DkgStatus::FinishedRound2);
        }

        Ok(DkgStatus::InProgress)
    }

    /// Returns an iterator of participants who have not sent their round2
    /// package.
    pub fn blame_round2_participants(&self) -> impl Iterator<Item = Identifier<C>> + '_ {
        self.participants
            .iter()
            .filter(|id| !self.round2_participants_set.contains(id))
            .copied()
    }

    /// Returns the public key package.
    pub fn public_key_package(&self) -> Result<PublicKeyPackage<C>, DkgDealerError<C>> {
        let commitments: BTreeMap<_, _> = self
            .round1_packages
            .iter()
            .map(|(id, (package, _))| (*id, package.commitment()))
            .collect();
        let public_key_package = PublicKeyPackage::from_dkg_commitments(&commitments)?;
        Ok(public_key_package)
    }

    /// Receives the [`Identifier`] and `round2_culprits` from the participant.
    pub fn receive_round2_culprits(
        &mut self,
        identifier: Identifier<C>,
        round2_culprits: BTreeSet<Identifier<C>>,
        temp_secret_key: SigningKey<C>,
    ) -> Result<DkgStatus, DkgDealerError<C>> {
        if !self.participants_set.contains(&identifier) {
            return Err(DkgDealerError::UnknownParticipant);
        }

        if round2_culprits
            .iter()
            .any(|id| !self.participants_set.contains(id))
        {
            return Err(DkgDealerError::UnknownParticipant);
        }

        // TODO: it should return other error, not InvalidStateTransition
        let (_, temp_public_key) = self
            .round1_packages
            .get(&identifier)
            .ok_or(DkgDealerError::InvalidStateTransition)?;

        if temp_public_key.to_element() != <C::Group>::generator() * temp_secret_key.to_scalar() {
            return Err(DkgDealerError::InvalidTempSecretKey);
        }

        // TODO: it should return other error, not InvalidStateTransition
        let round2_packages_encrypted = self
            .round2_packages_encrypted
            .get(&identifier)
            .cloned()
            .ok_or(DkgDealerError::InvalidStateTransition)?;

        let mut round2_packages = BTreeMap::new();

        // TODO: it should return other error, not InvalidStateTransition (maybe
        // DecryptionError?)
        for (sender_identifier, round2_package_encrypted) in round2_packages_encrypted {
            let (_, sender_temp_public_key) = self
                .round1_packages
                .get(&sender_identifier)
                .ok_or(DkgDealerError::InvalidStateTransition)?;

            let round2_package = decrypt_round2_package::<C, H>(
                round2_package_encrypted,
                sender_temp_public_key,
                &temp_secret_key,
            )
            .ok_or(DkgDealerError::InvalidStateTransition)?;

            round2_packages.insert(sender_identifier, round2_package);
        }

        for (sender_identifier, round2_package) in round2_packages {
            if round2_culprits.contains(&sender_identifier) {
                let ell = sender_identifier;
                let f_ell_i = *round2_package.signing_share();

                let commitment = self
                    .round1_packages
                    .get(&ell)
                    .ok_or(FrostError::PackageNotFound)?
                    .0
                    .commitment();

                let secret_share = SecretShare::new(identifier, f_ell_i, commitment.clone());

                if let Err(FrostError::InvalidSecretShare { .. }) = secret_share.verify() {
                    self.round2_culprits_set.insert(ell);
                }
            }
        }

        Ok(DkgStatus::InProgress)
    }

    /// Returns an iterator of participants who sent an invalid round2 package.
    pub fn round2_culprits(&self) -> impl Iterator<Item = Identifier<C>> + '_ {
        self.round2_culprits_set.iter().copied()
    }

    /// Tries to finish the Distributed Key Generation process.
    pub fn try_finish(&self) -> Result<DkgStatus, DkgDealerError<C>> {
        if !self.round2_culprits_set.is_empty() {
            return Err(DkgDealerError::InvalidSecretShares);
        }

        Ok(DkgStatus::FinishedRound3)
    }
}

/// Represents participant of Distributed Key Generation.
#[derive(Debug)]
pub struct Participant<C: Ciphersuite, H: Clone + BlockSizeUser + Digest> {
    identifier: Identifier<C>,
    temp_secret_key: SigningKey<C>,
    round1_secret_package: Option<round1::SecretPackage<C>>,
    round1_package: Option<Round1Package<C>>,
    round2_secret_package: Option<round2::SecretPackage<C>>,
    round1_packages: Option<BTreeMap<Identifier<C>, Round1Package<C>>>,
    round2_culprits_set: Option<BTreeSet<Identifier<C>>>,
    phantom: PhantomData<H>,
}

impl<C: Ciphersuite, H: Clone + BlockSizeUser + Digest> Participant<C, H> {
    /// Creates a new [`Participant`].
    pub fn new<RNG: RngCore + CryptoRng>(
        identifier: Identifier<C>,
        max_signers: u16,
        min_signers: u16,
        rng: &mut RNG,
    ) -> Result<Self, DkgParticipantError<C>> {
        keys::validate_num_of_signers(min_signers, max_signers)?;

        let temp_secret_key = SigningKey::new(rng);
        let temp_public_key = VerifyingKey::from(&temp_secret_key);

        let (round1_secret_package, round1_package) =
            dkg::part1(identifier, max_signers, min_signers, rng)?;

        Ok(Self {
            identifier,
            temp_secret_key,
            round1_secret_package: Some(round1_secret_package),
            round1_package: Some((round1_package, temp_public_key)),
            round2_secret_package: None,
            round1_packages: None,
            round2_culprits_set: None,
            phantom: PhantomData,
        })
    }

    /// Returns the identifier.
    pub fn identifier(&self) -> Identifier<C> {
        self.identifier
    }

    /// Returns the temporary secret key.
    pub fn temp_secret_key(&self) -> SigningKey<C> {
        self.temp_secret_key
    }

    /// Returns tuple of [`round1::Package<C>`] and [`VerifyingKey<C>`].
    pub fn round1_package(&mut self) -> Result<Round1Package<C>, DkgParticipantError<C>> {
        let round1_package = self
            .round1_package
            .take()
            .ok_or(DkgParticipantError::InvalidStateTransition)?;
        Ok(round1_package)
    }

    /// Receives `round1_packages` from the dealer.
    pub fn receive_round1_packages(
        &mut self,
        mut round1_packages: BTreeMap<Identifier<C>, Round1Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, Vec<u8>>, DkgParticipantError<C>> {
        let round1_secret_package = self
            .round1_secret_package
            .take()
            .ok_or(DkgParticipantError::InvalidStateTransition)?;
        round1_packages.remove(round1_secret_package.identifier());
        let (round2_secret_package, round2_packages) = dkg::part2(
            round1_secret_package,
            &round1_packages
                .iter()
                .map(|(id, (package, _))| (*id, package.clone()))
                .collect(),
        )?;

        self.round2_secret_package = Some(round2_secret_package);
        self.round1_packages = Some(round1_packages.clone());

        let mut round2_packages_encrypted = BTreeMap::new();

        // TODO: it should return other error, not InvalidStateTransition (maybe
        // EncryptionError?)
        for (receiver_identifier, round2_package) in round2_packages {
            let (_, receiver_temp_public_key) = round1_packages
                .get(&receiver_identifier)
                .ok_or(DkgParticipantError::InvalidStateTransition)?;

            let round2_package_encrypted = encrypt_round2_package::<C, H>(
                round2_package,
                receiver_temp_public_key,
                &self.temp_secret_key,
            )
            .ok_or(DkgParticipantError::InvalidStateTransition)?;

            round2_packages_encrypted.insert(receiver_identifier, round2_package_encrypted);
        }

        Ok(round2_packages_encrypted)
    }

    /// Receives `round2_packages_encrypted` from the dealer.
    pub fn receive_round2_packages_encrypted(
        &mut self,
        round2_packages_encrypted: BTreeMap<Identifier<C>, Vec<u8>>,
    ) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), DkgParticipantError<C>> {
        let round2_secret_package = self
            .round2_secret_package
            .take()
            .ok_or(DkgParticipantError::InvalidStateTransition)?;
        let round1_packages = self
            .round1_packages
            .take()
            .ok_or(DkgParticipantError::InvalidStateTransition)?;

        if round1_packages.len() != (round2_secret_package.max_signers() - 1) as usize {
            return Err(DkgParticipantError::Frost(
                FrostError::IncorrectNumberOfPackages,
            ));
        }
        if round1_packages.len() != round2_packages_encrypted.len() {
            return Err(DkgParticipantError::Frost(
                FrostError::IncorrectNumberOfPackages,
            ));
        }
        if round1_packages
            .keys()
            .any(|id| !round2_packages_encrypted.contains_key(id))
        {
            return Err(DkgParticipantError::Frost(FrostError::IncorrectPackage));
        }

        let mut round2_packages = BTreeMap::new();

        // TODO: it should return other error, not InvalidStateTransition (maybe
        // DecryptionError?)
        // TODO: when decryption failed round2_culprits_set should be updated
        for (sender_identifier, round2_package_encrypted) in round2_packages_encrypted {
            let (_, sender_temp_public_key) = round1_packages
                .get(&sender_identifier)
                .ok_or(DkgParticipantError::InvalidStateTransition)?;

            let round2_package = decrypt_round2_package::<C, H>(
                round2_package_encrypted,
                sender_temp_public_key,
                &self.temp_secret_key,
            )
            .ok_or(DkgParticipantError::InvalidStateTransition)?;

            round2_packages.insert(sender_identifier, round2_package);
        }

        let mut round2_culprits_set = BTreeSet::new();
        let mut signing_share = <<C::Group as Group>::Field>::zero();

        for (sender_identifier, round2_package) in round2_packages.iter() {
            let ell = *sender_identifier;
            let f_ell_i = *round2_package.signing_share();

            let commitment = round1_packages
                .get(&ell)
                .ok_or(FrostError::PackageNotFound)?
                .0
                .commitment();

            let secret_share = SecretShare::new(
                *round2_secret_package.identifier(),
                f_ell_i,
                commitment.clone(),
            );

            if let Err(FrostError::InvalidSecretShare { .. }) = secret_share.verify() {
                round2_culprits_set.insert(ell);
            }

            signing_share = signing_share + f_ell_i.to_scalar();
        }

        if !round2_culprits_set.is_empty() {
            self.round2_culprits_set = Some(round2_culprits_set);
            return Err(DkgParticipantError::InvalidSecretShares);
        }

        signing_share = signing_share + *round2_secret_package.secret_share();
        let signing_share = SigningShare::new(signing_share);

        let verifying_share = signing_share.into();

        let commitments: BTreeMap<_, _> = round1_packages
            .iter()
            .map(|(id, (package, _))| (*id, package.commitment()))
            .chain(iter::once((
                *round2_secret_package.identifier(),
                round2_secret_package.commitment(),
            )))
            .collect();
        let public_key_package = PublicKeyPackage::from_dkg_commitments(&commitments)?;

        let key_package = KeyPackage::new(
            *round2_secret_package.identifier(),
            signing_share,
            verifying_share,
            *public_key_package.verifying_key(),
            *round2_secret_package.min_signers(),
        );

        Ok((key_package, public_key_package))
    }

    /// Returns the round2 culprits.
    pub fn round2_culprits(&self) -> Result<BTreeSet<Identifier<C>>, DkgParticipantError<C>> {
        let round2_culprits_set = self
            .round2_culprits_set
            .clone()
            .ok_or(DkgParticipantError::InvalidStateTransition)?;
        Ok(round2_culprits_set)
    }
}
