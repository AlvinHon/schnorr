//! This module contains the definition of the struct `SchnorrP256Group` that implements trait `Group`.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::Group;
use std::ops::{Mul, Neg};

/// Schnorr group over P-256 curve, implements the [Group](super::Group) trait by using group elements of types [p256::ProjectivePoint] and [p256::Scalar].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrP256Group;

impl Group for SchnorrP256Group {
    type P = p256::ProjectivePoint;
    type F = p256::Scalar;
    type DeserializeError = ();

    fn generator(&self) -> Self::P {
        use p256::elliptic_curve::Group;
        p256::ProjectivePoint::generator()
    }

    fn dot(&self, p1: &Self::P, p2: &Self::P) -> Self::P {
        p1.add(p2)
    }

    fn mul_by_generator(&self, scalar: &Self::F) -> Self::P {
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

    fn is_equivalent_scalars(s1: &Self::F, s2: &Self::F) -> bool {
        s1 == s2
    }
    fn is_equivalent_points(p1: &Self::P, p2: &Self::P) -> bool {
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

    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::F, ()> {
        use p256::FieldBytes;
        let d_bytes = FieldBytes::from_slice(bytes);
        p256::NonZeroScalar::from_repr(*d_bytes)
            .into_option()
            .ok_or(())
            .map(|s| *s)
    }

    fn deserialize_point(bytes: &[u8]) -> Result<Self::P, ()> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::NistP256;

        p256::elliptic_curve::sec1::EncodedPoint::<NistP256>::from_bytes(bytes)
            .map_err(|_| ())
            .and_then(|p| {
                p256::ProjectivePoint::from_encoded_point(&p)
                    .into_option()
                    .ok_or(())
            })
            .map_err(|_| ())
    }

    fn random_scalar<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::F {
        *p256::NonZeroScalar::random(rng).as_ref()
    }
    fn random_element<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::P {
        self.generator()
            .mul(p256::NonZeroScalar::random(rng).as_ref())
    }
}
