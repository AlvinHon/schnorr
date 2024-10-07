//! # Schnorr Protocols
//!
//! Implementation of Schnorr Protocols:
//! - Schnorr Identification Protocol
//! - Schnorr Signature Scheme
//! - A variant of Schnorr Signature Scheme (based on elliptic curve cryptography)

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use num_bigint::BigUint;

pub mod dl;
pub use dl::*;

pub mod ec;
pub type SignatureSchemeECP256<H> = ec::SignatureScheme<H>;

pub mod identification;

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
