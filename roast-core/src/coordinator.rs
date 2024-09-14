use crate::{Error, MaliciousSignerError};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::mem;
use frost_core::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Ciphersuite,
    Error as FrostError, Identifier, Signature, SigningPackage,
};

type SessionId = u16;

#[derive(Debug)]
struct Session<C: Ciphersuite> {
    signing_package: SigningPackage<C>,
    signature_shares: BTreeMap<Identifier<C>, SignatureShare<C>>,
}

#[derive(Debug)]
pub enum SessionStatus<C: Ciphersuite> {
    InProgress,
    Started {
        signers: BTreeSet<Identifier<C>>,
        signing_package: SigningPackage<C>,
    },
    Finished {
        signature: Signature<C>,
    },
}

#[derive(Debug)]
pub struct Coordinator<C: Ciphersuite> {
    max_signers: u16,
    min_signers: u16,
    public_key_package: PublicKeyPackage<C>,
    message: Vec<u8>,
    responsive_signers: BTreeSet<Identifier<C>>,
    malicious_signers: BTreeMap<Identifier<C>, MaliciousSignerError>,
    latest_signing_commitments: BTreeMap<Identifier<C>, SigningCommitments<C>>,
    session_counter: SessionId,
    signer_session: BTreeMap<Identifier<C>, SessionId>,
    session: BTreeMap<SessionId, Session<C>>,
}

impl<C: Ciphersuite> Coordinator<C> {
    pub fn new(
        max_signers: u16,
        min_signers: u16,
        public_key_package: PublicKeyPackage<C>,
        message: Vec<u8>,
    ) -> Result<Self, Error<C>> {
        if min_signers < 2 {
            return Err(Error::Frost(FrostError::InvalidMinSigners));
        }

        if max_signers < 2 {
            return Err(Error::Frost(FrostError::InvalidMaxSigners));
        }

        if min_signers > max_signers {
            return Err(Error::Frost(FrostError::InvalidMinSigners));
        }

        Ok(Self {
            max_signers,
            min_signers,
            public_key_package,
            message,
            responsive_signers: BTreeSet::new(),
            malicious_signers: BTreeMap::new(),
            latest_signing_commitments: BTreeMap::new(),
            session_counter: 0,
            signer_session: BTreeMap::new(),
            session: BTreeMap::new(),
        })
    }

    pub fn receive(
        &mut self,
        identifier: Identifier<C>,
        signature_share: Option<SignatureShare<C>>,
        signing_commitments: SigningCommitments<C>,
    ) -> Result<SessionStatus<C>, Error<C>> {
        if let Some(err) = self.malicious_signers.get(&identifier).cloned() {
            return Err(Error::MaliciousSigner(err));
        }

        if self.responsive_signers.contains(&identifier) {
            return Err(self.mark_malicious(identifier, MaliciousSignerError::UnsolicitedReply));
        }

        if let Some(Session {
            signing_package,
            signature_shares,
        }) = self
            .signer_session
            .get(&identifier)
            .and_then(|session_id| self.session.get_mut(session_id))
        {
            let Some(signature_share) = signature_share else {
                return Err(
                    self.mark_malicious(identifier, MaliciousSignerError::InvalidSignatureShare)
                );
            };

            let verification_result = (|| -> Result<(), FrostError<C>> {
                let verifying_share = self
                    .public_key_package
                    .verifying_shares()
                    .get(&identifier)
                    .ok_or(FrostError::UnknownIdentifier)?;
                let verifying_key = self.public_key_package.verifying_key();

                frost_core::verify_signature_share(
                    identifier,
                    verifying_share,
                    &signature_share,
                    signing_package,
                    verifying_key,
                )
            })();

            if verification_result.is_err() {
                return Err(
                    self.mark_malicious(identifier, MaliciousSignerError::InvalidSignatureShare)
                );
            }

            signature_shares.insert(identifier, signature_share);

            if signature_shares.len() == self.min_signers as usize {
                let signature = frost_core::aggregate(
                    signing_package,
                    signature_shares,
                    &self.public_key_package,
                )?;
                return Ok(SessionStatus::Finished { signature });
            }
        }

        self.latest_signing_commitments
            .insert(identifier, signing_commitments);
        self.responsive_signers.insert(identifier);

        if self.responsive_signers.len() == self.min_signers as usize {
            self.session_counter += 1;
            let session_id = self.session_counter;

            let signing_commitments: BTreeMap<_, _> = self
                .responsive_signers
                .iter()
                .cloned()
                .filter_map(|identifier| {
                    self.latest_signing_commitments
                        .get(&identifier)
                        .cloned()
                        .map(|signing_commitments| (identifier, signing_commitments))
                })
                .collect();
            let signing_package = SigningPackage::new(signing_commitments, self.message.as_ref());

            for identifier in self.responsive_signers.iter().cloned() {
                self.signer_session.insert(identifier, session_id);
            }

            self.session.insert(
                session_id,
                Session {
                    signing_package: signing_package.clone(),
                    signature_shares: BTreeMap::new(),
                },
            );

            let signers = mem::take(&mut self.responsive_signers);
            return Ok(SessionStatus::Started {
                signers,
                signing_package,
            });
        }

        Ok(SessionStatus::InProgress)
    }

    fn mark_malicious(
        &mut self,
        identifier: Identifier<C>,
        malicious_signer_error: MaliciousSignerError,
    ) -> Error<C> {
        self.malicious_signers
            .insert(identifier, malicious_signer_error.clone());

        if self.malicious_signers.len() > (self.max_signers - self.min_signers) as usize {
            return Error::TooManyMaliciousSigners;
        }

        Error::MaliciousSigner(malicious_signer_error)
    }
}
