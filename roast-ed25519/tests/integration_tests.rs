use roast_core::{error::DkgError, tests};
use roast_ed25519::{error::RoastError, frost::rand_core::OsRng};

#[test]
fn test_dkg_basic() -> Result<(), DkgError<frost_ed25519::Ed25519Sha512>> {
    let mut rng = OsRng;
    tests::test_dkg_basic::<_, sha2::Sha512, _>(2, 3, &mut rng)?;
    Ok(())
}

#[test]
fn test_basic() -> Result<(), RoastError> {
    let mut rng = OsRng;
    tests::test_basic(2, 3, &mut rng)?;
    tests::test_basic(67, 100, &mut rng)?;
    Ok(())
}

#[test]
fn test_malicious() -> Result<(), RoastError> {
    let mut rng = OsRng;
    tests::test_malicious(2, 3, 1, &mut rng)?;
    tests::test_malicious(67, 100, 33, &mut rng)?;
    Ok(())
}
