//! Generic utility functions

use num_bigint::{BigUint, RandBigInt};

/// Create a BigUint number from a string (interpreted in base 10)
pub fn bignum(s: &[u8]) -> BigUint {
    BigUint::parse_bytes(s, 10).expect("Not a number")
}

/// Generate a random BigUint between `lower` (inclusive) and `upper` (exclusive)
pub fn random_bignum(lower: &BigUint, upper: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();

    // Note: upper bound is not inclusive
    rng.gen_biguint_range(lower, upper)
}
