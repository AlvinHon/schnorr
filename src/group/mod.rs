//! This module contains the definition of the `Group` trait and the `SchnorrGroup` struct.

use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub mod p256;
pub use p256::SchnorrP256Group;

/// Defines the operations that can be performed as the group with properties required for Schnorr's protocol.
pub trait Group: Clone {
    type P: Clone;
    type F: Clone;
    type DeserializeError;

    fn generator(&self) -> Self::P;

    // multiplication operations

    fn dot(&self, p1: &Self::P, p2: &Self::P) -> Self::P;
    fn mul_by_generator(&self, scalar: &Self::F) -> Self::P;
    fn mul(&self, p: &Self::P, scalar: &Self::F) -> Self::P;

    // addition operations

    // s1 + s2*s3 mod q
    fn add_mul_scalar(&self, s1: &Self::F, s2: &Self::F, s3: &Self::F) -> Self::F;
    fn neg(&self, scalar: &Self::F) -> Self::F;

    fn is_equivalent_scalars(s1: &Self::F, s2: &Self::F) -> bool;
    fn is_equivalent_points(p1: &Self::P, p2: &Self::P) -> bool;
    fn map_point(point: &Self::P) -> Vec<u8>;
    fn map_to_scalar(bytes: &[u8]) -> Self::F;

    // serialization and deserialization

    fn serialize_scalar(scalar: &Self::F) -> Vec<u8>;
    fn serialize_point(point: &Self::P) -> Vec<u8>;

    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::F, Self::DeserializeError>;
    fn deserialize_point(bytes: &[u8]) -> Result<Self::P, Self::DeserializeError>;

    // randomness function

    fn random_scalar<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::F;
    fn random_element<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::P;
}

/// Implement the [Group] trait by using group elements of type [BigUint](num_bigint::BigUint).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrGroup {
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

impl Group for SchnorrGroup {
    type P = BigUint;
    type F = BigUint;
    type DeserializeError = ();

    fn generator(&self) -> Self::P {
        self.a.clone()
    }

    fn dot(&self, p1: &BigUint, p2: &BigUint) -> BigUint {
        p1 * p2 % &self.p
    }

    fn mul_by_generator(&self, scalar: &BigUint) -> BigUint {
        self.a.modpow(scalar, &self.p)
    }

    fn mul(&self, p: &BigUint, scalar: &BigUint) -> BigUint {
        p.modpow(scalar, &self.p)
    }

    fn add_mul_scalar(&self, s1: &BigUint, s2: &BigUint, s3: &BigUint) -> BigUint {
        (s1 + s2 * s3) % &self.q
    }

    fn neg(&self, scalar: &BigUint) -> BigUint {
        &self.q - scalar
    }

    fn is_equivalent_scalars(s1: &BigUint, s2: &BigUint) -> bool {
        s1 == s2
    }
    fn is_equivalent_points(p1: &BigUint, p2: &BigUint) -> bool {
        p1 == p2
    }

    fn map_point(point: &BigUint) -> Vec<u8> {
        point.to_bytes_le()
    }

    fn map_to_scalar(bytes: &[u8]) -> BigUint {
        BigUint::from_bytes_le(bytes)
    }

    fn serialize_scalar(scalar: &BigUint) -> Vec<u8> {
        scalar.to_bytes_le()
    }

    fn serialize_point(point: &BigUint) -> Vec<u8> {
        point.to_bytes_le()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Result<BigUint, ()> {
        if bytes.is_empty() {
            return Err(());
        }
        Ok(BigUint::from_bytes_le(bytes))
    }

    fn deserialize_point(bytes: &[u8]) -> Result<BigUint, ()> {
        if bytes.is_empty() {
            return Err(());
        }
        Ok(BigUint::from_bytes_le(bytes))
    }

    fn random_scalar<R: RngCore>(&self, rng: &mut R) -> BigUint {
        use num_bigint::RandBigInt;
        rng.gen_biguint_range(&BigUint::from(1u32), &self.q)
    }
    fn random_element<R: RngCore>(&self, rng: &mut R) -> BigUint {
        use num_bigint::RandBigInt;
        rng.gen_biguint_range(&BigUint::from(1u32), &self.p)
    }
}
