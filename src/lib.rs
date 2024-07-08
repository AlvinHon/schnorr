//! # Schnorr Protocols
//!
//! Implementation of Schnorr Protocols:
//! - Schnorr Identification Protocol
//! - Schnorr Signature Scheme
//! - A variant of Schnorr Signature Scheme (based on elliptic curve cryptography)

pub mod identification;
use std::str::FromStr;

pub use identification::*;

pub mod signature;
use serde::{Deserialize, Serialize};
pub use signature::*;

use num_bigint::BigUint;

/// Hash function trait for Schnorr Protocols.
///
/// The trait is used to hash a byte array into a fixed-size byte array. Depends on the implementation, the output size may vary.
/// For example, 32-btyte hash is required for Schnorr Signature Scheme based on elliptic curve cryptography.
pub trait Hash {
    fn hash<T: AsRef<[u8]>>(value: T) -> Vec<u8>;
}

/// Signature trait for Schnorr Identification Protocol.
pub trait Sig {
    fn sign<T: AsRef<[u8]>>(value: T) -> Vec<u8>;
    fn verify<T: AsRef<[u8]>>(value: T, signature: &[u8]) -> bool;
}

/// Random number generator trait for Schnorr Protocols.
pub trait Rand {
    fn random_number(module: &BigUint) -> BigUint;
}

pub type Identity = BigUint;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SchnorrGroup {
    // p is a large prime
    // q is a large prime divisor of p-1
    // a is a generator of the group of order q, i.e., a^q mod p = 1 by Fermat's Little Theorem.
    p: BigUint,
    q: BigUint,
    a: BigUint,
}

impl SchnorrGroup {
    /// Create a SchnorrGroup from string representation of p, q, and a, where p and q are large prime numbers
    /// and a is a generator of the group of order q. Return None if a is not a valid generator (i.e. a^q mod p != 1)
    pub(crate) fn from_str(p: &str, q: &str, a: &str) -> Option<Self> {
        // check if a is a valid generator
        let p = BigUint::from_str(p).ok()?;
        let q = BigUint::from_str(q).ok()?;
        let a = BigUint::from_str(a).ok()?;
        if a.modpow(&q, &p) != BigUint::from(1u32) {
            return None;
        }
        Some(Self { p, q, a })
    }
}
