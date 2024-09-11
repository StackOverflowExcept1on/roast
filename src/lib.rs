pub use coordinator::*;
pub use error::*;
pub use participant::*;
pub(crate) use verification::*;

mod coordinator;
mod error;
mod participant;
mod verification;

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::{self as frost, rand_core::OsRng};
    use std::collections::BTreeMap;

    #[test]
    fn it_works() -> Result<()> {
        let mut rng = OsRng;
        let max_signers = 5;
        let min_signers = 3;
        let (secret_shares, public_key_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            rng,
        )?;

        let mut coordinator = Coordinator::new(
            max_signers,
            min_signers,
            public_key_package,
            b"message to sign".into(),
        );
        let mut participants: BTreeMap<_, _> = BTreeMap::new();

        for (identifier, secret_share) in secret_shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            participants.insert(identifier, Participant::new(key_package, &mut rng));
        }

        let mut session_statuses1 = Vec::new();
        for index in 1..=min_signers {
            let identifier = index.try_into()?;
            let participant = participants.get(&identifier).unwrap();
            let response =
                coordinator.receive(identifier, None, participant.signing_commitments())?;
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
                let participant = participants.get_mut(&identifier).unwrap();
                let signature_share = participant.receive(signing_package, &mut rng)?;
                let response = coordinator.receive(
                    identifier,
                    Some(signature_share),
                    participant.signing_commitments(),
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
}
