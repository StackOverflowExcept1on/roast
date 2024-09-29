//! Distributed Key Generation types.

use crate::error::{DistributedKeyGenerationError, Error, FrostError};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use frost_core::{
    keys::{
        dkg::{self, round1, round2},
        KeyPackage, PublicKeyPackage,
    },
    Ciphersuite, Identifier,
};
use rand_core::{CryptoRng, RngCore};

/// Represents all possible Distributed Key Generation statuses.
#[derive(Debug)]
pub enum DistributedKeyGenerationStatus<C: Ciphersuite> {
    /// Distributed Key Generation still in progress.
    InProgress,
    /// Finished round1 of Distributed Key Generation.
    FinishedRound1,
    /// Finished round2 of Distributed Key Generation.
    FinishedRound2,
    /// Finished round3 of Distributed Key Generation.
    FinishedRound3 {
        /// Public key package.
        public_key_package: PublicKeyPackage<C>,
    },
}

/// Represents trusted third party that can be used for Distributed Key
/// Generation.
#[derive(Debug)]
pub struct TrustedThirdParty<C: Ciphersuite> {
    max_signers: u16,
    min_signers: u16,
    participants: Vec<Identifier<C>>,
    participants_set: BTreeSet<Identifier<C>>,
    round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
    round2_packages: BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, round2::Package<C>>>,
    round2_participants_set: BTreeSet<Identifier<C>>,
}

impl<C: Ciphersuite> TrustedThirdParty<C> {
    /// Creates a new [`TrustedThirdParty`].
    pub fn new(
        max_signers: u16,
        min_signers: u16,
        participants: Vec<Identifier<C>>,
    ) -> Result<Self, Error<C>> {
        // TODO: https://github.com/ZcashFoundation/frost/issues/736

        if min_signers < 2 {
            return Err(Error::Frost(FrostError::InvalidMinSigners));
        }

        if max_signers < 2 {
            return Err(Error::Frost(FrostError::InvalidMaxSigners));
        }

        if min_signers > max_signers {
            return Err(Error::Frost(FrostError::InvalidMinSigners));
        }

        let participants_set = BTreeSet::from_iter(participants.clone());
        if participants_set.len() != participants.len() {
            return Err(Error::Dkg(
                DistributedKeyGenerationError::DuplicateParticipants,
            ));
        }

        Ok(Self {
            max_signers,
            min_signers,
            participants,
            participants_set,
            round1_packages: BTreeMap::new(),
            round2_packages: BTreeMap::new(),
            round2_participants_set: BTreeSet::new(),
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

    /// Returns the participants.
    pub fn participants(&self) -> &[Identifier<C>] {
        &self.participants
    }

    /// Returns the round1 packages.
    pub fn round1_packages(&self) -> &BTreeMap<Identifier<C>, round1::Package<C>> {
        &self.round1_packages
    }

    /// Returns the round2 packages.
    pub fn round2_packages(
        &self,
    ) -> &BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, round2::Package<C>>> {
        &self.round2_packages
    }

    /// Receives the [`Identifier`] and [`round1::Package<C>`] from the
    /// participant.
    pub fn receive_round1_package(
        &mut self,
        identifier: Identifier<C>,
        round1_package: round1::Package<C>,
    ) -> Result<DistributedKeyGenerationStatus<C>, Error<C>> {
        if !self.participants_set.contains(&identifier) {
            return Err(Error::Dkg(
                DistributedKeyGenerationError::UnknownParticipant,
            ));
        }

        if round1_package.commitment().coefficients().len() != self.min_signers as usize {
            return Err(Error::Frost(FrostError::IncorrectNumberOfCommitments));
        }

        dkg::verify_proof_of_knowledge(
            identifier,
            round1_package.commitment(),
            round1_package.proof_of_knowledge(),
        )?;

        self.round1_packages.insert(identifier, round1_package);

        if self.round1_packages.len() == self.max_signers as usize {
            return Ok(DistributedKeyGenerationStatus::FinishedRound1);
        }

        Ok(DistributedKeyGenerationStatus::InProgress)
    }

    /// Returns an iterator of participants who have not sent their round1
    /// package.
    pub fn blame_round1_participants(&self) -> impl Iterator<Item = Identifier<C>> + '_ {
        self.participants
            .iter()
            .filter(|id| !self.round1_packages.contains_key(id))
            .copied()
    }

    /// Receives the [`Identifier`] and `round2_packages` from the participant.
    pub fn receive_round2_packages(
        &mut self,
        identifier: Identifier<C>,
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<DistributedKeyGenerationStatus<C>, Error<C>> {
        if !self.participants_set.contains(&identifier) {
            return Err(Error::Dkg(
                DistributedKeyGenerationError::UnknownParticipant,
            ));
        }

        if round2_packages.len() != (self.max_signers - 1) as usize {
            return Err(Error::Frost(FrostError::IncorrectNumberOfPackages));
        }

        if self
            .participants
            .iter()
            .filter(|id| identifier.ne(id))
            .any(|id| !round2_packages.contains_key(id))
        {
            return Err(Error::Frost(FrostError::IncorrectPackage));
        }

        for (receiver_identifier, round2_package) in round2_packages {
            self.round2_packages
                .entry(receiver_identifier)
                .or_default()
                .insert(identifier, round2_package);
        }

        self.round2_participants_set.insert(identifier);

        if self.round2_participants_set.len() == self.max_signers as usize {
            return Ok(DistributedKeyGenerationStatus::FinishedRound2);
        }

        Ok(DistributedKeyGenerationStatus::InProgress)
    }

    /// Returns an iterator of participants who have not sent their round2
    /// package.
    pub fn blame_round2_participants(&self) -> impl Iterator<Item = Identifier<C>> + '_ {
        self.participants
            .iter()
            .filter(|id| !self.round2_participants_set.contains(id))
            .copied()
    }
}

/// Represents participant of Distributed Key Generation.
#[derive(Debug)]
pub struct Participant<C: Ciphersuite> {
    identifier: Identifier<C>,
    // TODO: ^ remove identifier, https://github.com/ZcashFoundation/frost/issues/737
    round1_secret_package: round1::SecretPackage<C>,
    round1_package: round1::Package<C>,
    // TODO: ^ maybe group into one Option<T> to use .take()
    round2_secret_package: Option<round2::SecretPackage<C>>,
    round2_packages: Option<BTreeMap<Identifier<C>, round2::Package<C>>>,
    // TODO: ^ maybe group into one Option<T>
}

impl<C: Ciphersuite> Participant<C> {
    /// Creates a new [`Participant`].
    pub fn new<RNG: RngCore + CryptoRng>(
        identifier: Identifier<C>,
        max_signers: u16,
        min_signers: u16,
        rng: &mut RNG,
    ) -> Result<Self, Error<C>> {
        let (round1_secret_package, round1_package) =
            dkg::part1(identifier, max_signers, min_signers, rng)?;

        Ok(Self {
            identifier,
            round1_secret_package,
            round1_package,
            round2_secret_package: None,
            round2_packages: None,
        })
    }

    /// Returns the identifier.
    pub fn identifier(&self) -> Identifier<C> {
        self.identifier
    }

    /// Returns the [`round1::Package<C>`], i.e. the public part of
    /// [`round1::SecretPackage<C>`] that is used for the first round of DKG.
    pub fn round1_package(&self) -> round1::Package<C> {
        self.round1_package.clone()
    }

    /// TODO.
    pub fn receive_round1_packages(
        &mut self,
        mut round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Error<C>> {
        // TODO: round1_packages.remove(&self.round1_secret_package.identifier());
        round1_packages.remove(&self.identifier);

        // TODO: consider using Option<T> for round1_secret_package (use .take())
        let (round2_secret_package, round2_packages) =
            dkg::part2(self.round1_secret_package.clone(), &round1_packages)?;

        self.round2_secret_package = Some(round2_secret_package);
        self.round2_packages = Some(round2_packages.clone());

        Ok(round2_packages)
    }

    /// TODO.
    pub fn receive_round2_packages(
        &mut self,
        mut round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>> {
        let Some(round2_secret_package) = self.round2_secret_package.as_ref() else {
            // TODO: handle this in a better way
            panic!("round2_secret_package is None");
        };

        // TODO: round1_packages.remove(&self.round1_secret_package.identifier());
        round1_packages.remove(&self.identifier);
        // TODO: ^ maybe store this in a field as Option<T>

        let (key_package, public_key_package) =
            dkg::part3(round2_secret_package, &round1_packages, &round2_packages)?;

        Ok((key_package, public_key_package))
    }
}
