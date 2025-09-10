//! This module contains the definition of the `Group` trait and the `SchnorrGroup` struct.

use dashu::integer::{fast_div::ConstDivisor, UBig};
use rand::Rng;
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
    p: UBig,
    q: UBig,
    a: UBig,
}

impl SchnorrGroup {
    /// Create a SchnorrGroup from string representation of p, q, and a, where p and q are large prime numbers
    /// and a is a generator of the group of order q. Return None if a is not a valid generator (i.e. a^q mod p != 1)
    pub(crate) fn from_str(p: &str, q: &str, a: &str) -> Option<Self> {
        // check if a is a valid generator
        let p = UBig::from_str(p).ok()?;
        let q = UBig::from_str(q).ok()?;
        let a = UBig::from_str(a).ok()?;
        let modp = ConstDivisor::new(p.clone());

        if modp.reduce(a.clone()).pow(&q) != modp.reduce(1) {
            return None;
        }
        Some(Self { p, q, a })
    }
}

impl Group for SchnorrGroup {
    type P = UBig;
    type F = UBig;
    type DeserializeError = ();

    fn generator(&self) -> Self::P {
        self.a.clone()
    }

    fn dot(&self, p1: &UBig, p2: &UBig) -> UBig {
        ConstDivisor::new(self.p.clone()).reduce(p1 * p2).residue()
    }

    fn mul_by_generator(&self, scalar: &UBig) -> UBig {
        ConstDivisor::new(self.p.clone())
            .reduce(self.a.clone())
            .pow(scalar)
            .residue()
    }

    fn mul(&self, p: &UBig, scalar: &UBig) -> UBig {
        ConstDivisor::new(self.p.clone())
            .reduce(p.clone())
            .pow(scalar)
            .residue()
    }

    fn add_mul_scalar(&self, s1: &UBig, s2: &UBig, s3: &UBig) -> UBig {
        ConstDivisor::new(self.q.clone())
            .reduce(s1 + s2 * s3)
            .residue()
    }

    fn neg(&self, scalar: &UBig) -> UBig {
        &self.q - scalar
    }

    fn is_equivalent_scalars(s1: &UBig, s2: &UBig) -> bool {
        s1 == s2
    }
    fn is_equivalent_points(p1: &UBig, p2: &UBig) -> bool {
        p1 == p2
    }

    fn map_point(point: &UBig) -> Vec<u8> {
        point.to_le_bytes().to_vec()
    }

    fn map_to_scalar(bytes: &[u8]) -> UBig {
        UBig::from_le_bytes(bytes)
    }

    fn serialize_scalar(scalar: &UBig) -> Vec<u8> {
        scalar.to_le_bytes().to_vec()
    }

    fn serialize_point(point: &UBig) -> Vec<u8> {
        point.to_le_bytes().to_vec()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Result<UBig, ()> {
        if bytes.is_empty() {
            return Err(());
        }
        Ok(UBig::from_le_bytes(bytes))
    }

    fn deserialize_point(bytes: &[u8]) -> Result<UBig, ()> {
        if bytes.is_empty() {
            return Err(());
        }
        Ok(UBig::from_le_bytes(bytes))
    }

    fn random_scalar<R: Rng>(&self, rng: &mut R) -> UBig {
        rng.gen_range(UBig::ONE..self.q.clone())
    }

    fn random_element<R: Rng>(&self, rng: &mut R) -> UBig {
        rng.gen_range(UBig::ONE..self.p.clone())
    }
}
