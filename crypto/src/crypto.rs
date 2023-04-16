//! Collection of encryption and digital signature algorithms

pub mod dsa;
pub mod elgamal;
pub mod rsa;

use crate::utils::random_bignum;
use num_bigint::BigUint;
use sha256::digest;

/// Single number or a pair of numbers (depending on the algorithm)
#[derive(Debug)]
pub enum Ciphertext {
    Single(BigUint),
    Pair(BigUint, BigUint),
}

/// Single number or a pair of numbers (depending on the algorithm)
#[derive(Debug)]
pub enum Signature {
    Single(BigUint),
    Pair(BigUint, BigUint),
}

/// Add encrypt/decrypt capabilities to the algorithm
pub trait Encrypt {
    fn encrypt(&self, m: &BigUint) -> Ciphertext;
    fn decrypt(&self, c: &Ciphertext) -> BigUint;
}

/// Add sign/verify capabilities to the algorithm
pub trait Sign {
    fn hash(m: &BigUint) -> BigUint;
    fn sign(&self, m: &BigUint) -> Signature;
    fn verify(&self, m: &BigUint, sig: &Signature) -> bool;
}
