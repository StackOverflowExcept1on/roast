use crate::Result;
use frost_secp256k1::{
    self as frost,
    rand_core::{CryptoRng, RngCore},
};

#[derive(Debug)]
pub struct Participant {
    key_package: frost::keys::KeyPackage,
    signing_nonces: frost::round1::SigningNonces,
}

impl Participant {
    pub fn new<RNG: RngCore + CryptoRng>(
        key_package: frost::keys::KeyPackage,
        rng: &mut RNG,
    ) -> Self {
        let (signing_nonces, _) = frost::round1::commit(key_package.signing_share(), rng);
        Self {
            key_package,
            signing_nonces,
        }
    }

    pub fn signing_commitments(&self) -> frost::round1::SigningCommitments {
        *self.signing_nonces.commitments()
    }

    pub fn receive<RNG: RngCore + CryptoRng>(
        &mut self,
        signing_package: &frost::SigningPackage,
        rng: &mut RNG,
    ) -> Result<frost::round2::SignatureShare> {
        let signature_share =
            frost::round2::sign(signing_package, &self.signing_nonces, &self.key_package)?;

        let (signing_nonces, _) = frost::round1::commit(self.key_package.signing_share(), rng);
        self.signing_nonces = signing_nonces;

        Ok(signature_share)
    }
}
