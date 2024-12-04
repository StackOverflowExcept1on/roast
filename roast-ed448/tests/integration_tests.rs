use roast_core::tests;
use roast_ed448::{error::RoastError, frost::rand_core::OsRng};

// TODO: replace `sha3::Shake256` with something else to support dkg tests

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
