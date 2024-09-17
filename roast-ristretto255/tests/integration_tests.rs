use roast_ristretto255::{frost::rand_core::OsRng, Error};

#[test]
fn test_basic() -> Result<(), Error> {
    let mut rng = OsRng;
    roast_core::tests::test_basic(&mut rng)
}
