//! # Schnorr Protocols
//!
//! Implementation of Schnorr Protocols:
//! - Schnorr Identification Protocol
//! - Schnorr Signature Scheme
//! - A variant of Schnorr Signature Scheme (based on elliptic curve cryptography)

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use digest::Digest;
use num_bigint::BigUint;
use std::ops::{Mul, Neg};

pub mod dl;
pub use dl::*;

pub mod identification;

/// Instantiate a Schnorr Signature Protocol from string representation of p, q, and a.
pub fn signature_scheme<H: Digest>(
    p: &str,
    q: &str,
    a: &str,
) -> Option<SignatureScheme<SchnorrGroup, H>> {
    let group = SchnorrGroup::from_str(p, q, a)?;
    Some(SignatureScheme {
        group,
        _phantom: std::marker::PhantomData,
    })
}

/// Instantiate a Schnorr Identification Protocol from string representation of p, q, and a.
pub fn identification_protocol(
    p: &str,
    q: &str,
    a: &str,
) -> Option<identification::Identification<SchnorrGroup>> {
    SchnorrGroup::from_str(p, q, a).map(|group| identification::Identification { group })
}

/// Instantiate a Schnorr Signature Protocol based on elliptic curve p256.
pub fn signature_scheme_p256<H: Digest>() -> SignatureScheme<SchnorrP256Group, H> {
    let group = SchnorrP256Group;
    SignatureScheme {
        group,
        _phantom: std::marker::PhantomData,
    }
}

/// Instantiate a Schnorr Identification Protocol based on elliptic curve p256.
pub fn identificatio_protocol_p256() -> identification::Identification<SchnorrP256Group> {
    identification::Identification {
        group: SchnorrP256Group,
    }
}

pub trait Group: Clone {
    type P: Clone;
    type F: Clone;

    fn generator(&self) -> Self::P;

    // multiplication operations

    fn dot(&self, p1: &Self::P, p2: &Self::P) -> Self::P;
    fn gmul(&self, scalar: &Self::F) -> Self::P;
    fn mul(&self, p: &Self::P, scalar: &Self::F) -> Self::P;

    // addition operations

    // s1 + s2*s3 mod q
    fn add_mul_scalar(&self, s1: &Self::F, s2: &Self::F, s3: &Self::F) -> Self::F;
    fn neg(&self, scalar: &Self::F) -> Self::F;

    fn is_equavalent_scalars(s1: &Self::F, s2: &Self::F) -> bool;
    fn is_equavalent_points(p1: &Self::P, p2: &Self::P) -> bool;
    fn map_point(point: &Self::P) -> Vec<u8>;
    fn map_to_scalar(bytes: &[u8]) -> Self::F;

    // serialization and deserialization

    fn serialize_scalar(scalar: &Self::F) -> Vec<u8>;
    fn serialize_point(point: &Self::P) -> Vec<u8>;

    fn deserialize_scalar(bytes: &[u8]) -> Self::F;
    fn deserialize_point(bytes: &[u8]) -> Self::P;

    // randomness function

    fn rand<R: rand::RngCore + rand::CryptoRng>(&self, rng: &mut R) -> Self::F;
}

#[derive(Clone, Serialize, Deserialize)]
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
    fn from_str(p: &str, q: &str, a: &str) -> Option<Self> {
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

    fn generator(&self) -> Self::P {
        self.a.clone()
    }

    fn dot(&self, p1: &BigUint, p2: &BigUint) -> BigUint {
        p1 * p2 % &self.p
    }

    fn gmul(&self, scalar: &BigUint) -> BigUint {
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

    fn is_equavalent_scalars(s1: &BigUint, s2: &BigUint) -> bool {
        s1 == s2
    }
    fn is_equavalent_points(p1: &BigUint, p2: &BigUint) -> bool {
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

    fn deserialize_scalar(bytes: &[u8]) -> BigUint {
        BigUint::from_bytes_le(bytes)
    }

    fn deserialize_point(bytes: &[u8]) -> BigUint {
        BigUint::from_bytes_le(bytes)
    }

    fn rand<R: rand::RngCore>(&self, rng: &mut R) -> BigUint {
        use num_bigint::RandBigInt;
        rng.gen_biguint_range(&BigUint::from(1u32), &self.q)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SchnorrP256Group;

impl Group for SchnorrP256Group {
    type P = p256::ProjectivePoint;
    type F = p256::Scalar;

    fn generator(&self) -> Self::P {
        use p256::elliptic_curve::Group;
        p256::ProjectivePoint::generator()
    }

    fn dot(&self, p1: &Self::P, p2: &Self::P) -> Self::P {
        p1.add(p2)
    }

    fn gmul(&self, scalar: &Self::F) -> Self::P {
        self.generator().mul(scalar.as_ref())
    }

    fn mul(&self, p: &Self::P, scalar: &Self::F) -> Self::P {
        p.mul(scalar.as_ref())
    }

    fn add_mul_scalar(&self, s1: &Self::F, s2: &Self::F, s3: &Self::F) -> Self::F {
        s1.add(&s2.multiply(s3))
    }

    fn neg(&self, scalar: &Self::F) -> Self::F {
        scalar.neg()
    }

    fn is_equavalent_scalars(s1: &Self::F, s2: &Self::F) -> bool {
        s1 == s2
    }
    fn is_equavalent_points(p1: &Self::P, p2: &Self::P) -> bool {
        p1 == p2
    }

    fn map_point(point: &Self::P) -> Vec<u8> {
        use p256::elliptic_curve::point::AffineCoordinates;
        point.to_affine().x().to_vec()
    }

    fn map_to_scalar(bytes: &[u8]) -> Self::F {
        p256::elliptic_curve::ScalarPrimitive::<p256::NistP256>::from_slice(bytes)
            .unwrap()
            .into()
    }

    fn serialize_scalar(scalar: &Self::F) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    fn serialize_point(point: &Self::P) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        point.to_encoded_point(false).as_bytes().to_vec()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Self::F {
        use p256::FieldBytes;
        let d_bytes = FieldBytes::from_slice(bytes);
        p256::NonZeroScalar::from_repr(*d_bytes)
            .into_option()
            .unwrap()
            .as_ref()
            .clone()
    }

    fn deserialize_point(bytes: &[u8]) -> Self::P {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::NistP256;

        p256::elliptic_curve::sec1::EncodedPoint::<NistP256>::from_bytes(bytes)
            .map_err(|_| ())
            .and_then(|p| {
                p256::ProjectivePoint::from_encoded_point(&p)
                    .into_option()
                    .ok_or(())
            })
            .unwrap()
    }

    fn rand<R: rand::RngCore + rand::CryptoRng>(&self, rng: &mut R) -> Self::F {
        p256::NonZeroScalar::random(rng).as_ref().clone()
    }
}
