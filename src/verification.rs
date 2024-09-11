//! Copy-paste of [`frost_core::aggregate()`].

use frost_secp256k1 as frost;

pub trait SignatureShareExt {
    fn verify2(
        &self,
        signature_share_identifier: &frost::Identifier,
        signing_package: &frost::SigningPackage,
        pubkeys: &frost::keys::PublicKeyPackage,
    ) -> Result<(), frost::Error>;
}

impl SignatureShareExt for frost::round2::SignatureShare {
    fn verify2(
        &self,
        signature_share_identifier: &frost::Identifier,
        signing_package: &frost::SigningPackage,
        pubkeys: &frost::keys::PublicKeyPackage,
    ) -> Result<(), frost::Error> {
        let binding_factor_list =
            frost_core::compute_binding_factor_list(signing_package, pubkeys.verifying_key(), &[])?;
        let group_commitment =
            frost_core::compute_group_commitment(signing_package, &binding_factor_list)?;

        let challenge = frost_core::challenge(
            &group_commitment.to_element(),
            pubkeys.verifying_key(),
            signing_package.message().as_slice(),
        )?;

        let signer_pubkey = pubkeys
            .verifying_shares()
            .get(signature_share_identifier)
            .ok_or(frost::Error::UnknownIdentifier)?;

        let lambda_i =
            frost_core::derive_interpolating_value(signature_share_identifier, signing_package)?;

        let binding_factor = binding_factor_list
            .get(signature_share_identifier)
            .ok_or(frost::Error::UnknownIdentifier)?;

        #[allow(non_snake_case)]
        let R_share = signing_package
            .signing_commitment(signature_share_identifier)
            .ok_or(frost::Error::UnknownIdentifier)?
            .to_group_commitment_share(binding_factor);

        self.verify(
            *signature_share_identifier,
            &R_share,
            signer_pubkey,
            lambda_i,
            &challenge,
        )
    }
}
