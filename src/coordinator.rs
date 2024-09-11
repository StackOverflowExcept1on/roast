use crate::{Error, MaliciousSignerError, Result, SignatureShareExt};
use frost_secp256k1 as frost;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    mem,
};

type SessionId = u16;

#[derive(Debug)]
struct Session {
    signing_package: frost::SigningPackage,
    signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
}

#[derive(Debug)]
pub enum SessionStatus {
    InProgress,
    Started {
        signers: HashSet<frost::Identifier>,
        signing_package: frost::SigningPackage,
    },
    Finished {
        signature: frost::Signature,
    },
}

#[derive(Debug)]
pub struct Coordinator {
    max_signers: u16,
    min_signers: u16,
    public_key_package: frost::keys::PublicKeyPackage,
    message: Vec<u8>,
    responsive_signers: HashSet<frost::Identifier>,
    malicious_signers: HashMap<frost::Identifier, MaliciousSignerError>,
    latest_signing_commitments: HashMap<frost::Identifier, frost::round1::SigningCommitments>,
    session_counter: SessionId,
    signer_session: HashMap<frost::Identifier, SessionId>,
    session: HashMap<SessionId, Session>,
}

impl Coordinator {
    pub fn new(
        max_signers: u16,
        min_signers: u16,
        public_key_package: frost::keys::PublicKeyPackage,
        message: Vec<u8>,
    ) -> Self {
        Self {
            max_signers,
            min_signers,
            public_key_package,
            message,
            responsive_signers: HashSet::new(),
            malicious_signers: HashMap::new(),
            latest_signing_commitments: HashMap::new(),
            session_counter: 0,
            signer_session: HashMap::new(),
            session: HashMap::new(),
        }
    }

    pub fn receive(
        &mut self,
        identifier: frost::Identifier,
        signature_share: Option<frost::round2::SignatureShare>,
        signing_commitments: frost::round1::SigningCommitments,
    ) -> Result<SessionStatus> {
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

            if signature_share
                .verify2(&identifier, signing_package, &self.public_key_package)
                .is_err()
            {
                return Err(
                    self.mark_malicious(identifier, MaliciousSignerError::InvalidSignatureShare)
                );
            }

            signature_shares.insert(identifier, signature_share);

            if signature_shares.len() == self.min_signers as usize {
                let signature =
                    frost::aggregate(signing_package, signature_shares, &self.public_key_package)?;
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
            let signing_package =
                frost::SigningPackage::new(signing_commitments, self.message.as_ref());

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

    pub fn mark_malicious(
        &mut self,
        identifier: frost::Identifier,
        malicious_signer_error: MaliciousSignerError,
    ) -> Error {
        self.malicious_signers
            .insert(identifier, malicious_signer_error.clone());

        if self.malicious_signers.len() > (self.max_signers - self.min_signers) as usize {
            return Error::TooManyMaliciousSigners;
        }

        Error::MaliciousSigner(malicious_signer_error)
    }
}
