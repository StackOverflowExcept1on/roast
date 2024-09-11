use frost_secp256k1 as frost;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug, Clone)]
pub enum MaliciousSignerError {
    #[error("Unsolicited reply")]
    UnsolicitedReply,
    #[error("Invalid signature share")]
    InvalidSignatureShare,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("FROST error: {0}")]
    Frost(#[from] frost::Error),
    #[error("Malicious signer: {0}")]
    MaliciousSigner(#[from] MaliciousSignerError),
    #[error("Too many malicious signers")]
    TooManyMaliciousSigners,
}
