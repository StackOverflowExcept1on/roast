use crate::{
    frost_core::{
        keys::KeyPackage,
        round1::{self, SigningCommitments, SigningNonces},
        round2::{self, SignatureShare},
        Ciphersuite, SigningPackage,
    },
    Error,
};
use rand_core::{CryptoRng, RngCore};

/// Represents signer of ROAST protocol.
#[derive(Debug)]
pub struct Signer<C: Ciphersuite> {
    key_package: KeyPackage<C>,
    signing_nonces: SigningNonces<C>,
}

impl<C: Ciphersuite> Signer<C> {
    /// Creates a new [`Signer`] and generates [`SigningNonces`] for the first round of FROST.
    pub fn new<RNG: RngCore + CryptoRng>(key_package: KeyPackage<C>, rng: &mut RNG) -> Self {
        let (signing_nonces, _) = round1::commit(key_package.signing_share(), rng);
        Self {
            key_package,
            signing_nonces,
        }
    }

    /// Returns the [`SigningCommitments`], i.e. the public part of
    /// [`SigningNonces`] that is used for the first round of FROST.
    pub fn signing_commitments(&self) -> SigningCommitments<C> {
        *self.signing_nonces.commitments()
    }

    /// Receives a [`SigningPackage`] from the coordinator to create a
    /// [`SignatureShare`] that is used in the second round of FROST.
    ///
    /// Also regenerates [`SigningNonces`] for the first round of FROST. The
    /// caller should take care to send the coordinator a new
    /// [`SigningCommitments`].
    pub fn receive<RNG: RngCore + CryptoRng>(
        &mut self,
        signing_package: &SigningPackage<C>,
        rng: &mut RNG,
    ) -> Result<SignatureShare<C>, Error<C>> {
        let signature_share =
            round2::sign(signing_package, &self.signing_nonces, &self.key_package)?;

        let (signing_nonces, _) = round1::commit(self.key_package.signing_share(), rng);
        self.signing_nonces = signing_nonces;

        Ok(signature_share)
    }
}
