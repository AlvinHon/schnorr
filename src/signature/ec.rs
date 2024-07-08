//! Implementation of Schnorr Signature Scheme (a varient scheme by using elliptic curve cryptography)

use crate::Hash;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::Group;
use std::ops::{Mul, Neg};

/// Schnorr Signature Scheme based on elliptic curve cryptography.
/// The scheme consists of the following steps:
/// 1. Generate a key pair (d, p) where p = -dG.
/// 2. Sign a message m with the key pair (d, p) by generating a random number k and calculate r = kG and e = H(r_x || p_x || m).
/// 3. Calculate s = k + e*d.
/// 4. The signature is (e, s).
/// 5. Verify the signature by calculating r_v = sG + eP and e_v = H(r_x || p_x || m). If e_v == e, then the signature is valid.
///
/// The scheme is based on the elliptic curve cryptography with the curve P-256.
/// The hash function H is used to hash a byte array into a 32-byte array.
#[derive(Default)]
pub struct SignatureScheme<H: Hash> {
    /// generator point
    g: p256::AffinePoint,
    _phantom: std::marker::PhantomData<H>,
}

impl<H: Hash> SignatureScheme<H> {
    pub fn new() -> Self {
        let g = p256::ProjectivePoint::generator().to_affine();

        Self {
            g,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn generate_key<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
    ) -> (SigningKey, PublicKey) {
        // p = -dG
        let d = p256::NonZeroScalar::random(rng);
        let p = self.g.mul(d.neg().as_ref());
        (SigningKey { d }, PublicKey { p })
    }

    pub fn sign<R: rand::CryptoRng + rand::RngCore, M: AsRef<[u8]>>(
        &self,
        rng: &mut R,
        key: &SigningKey,
        pub_key: &PublicKey,
        message: M,
    ) -> Signature {
        // r = kG
        let k = p256::NonZeroScalar::random(rng);
        let r = self.g.mul(k.as_ref());

        // e = H(r_x || p_x || m)
        let r_x = r.to_affine().x().to_vec();
        let p_x = pub_key.p.to_affine().x().to_vec();
        let e = p256::elliptic_curve::ScalarPrimitive::<p256::NistP256>::from_slice(&H::hash(
            [r_x, p_x, message.as_ref().to_vec()].concat(),
        ))
        .unwrap();
        let e = p256::Scalar::from(e);
        // s = k + e*d
        let s = k.add(&e.multiply(&key.d));
        Signature { e, s }
    }

    pub fn verify(&self, key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        // r_v = sG + eP
        let r_v = self
            .g
            .mul(signature.s.as_ref())
            .add(&key.p.mul(signature.e.as_ref()));
        // ev = H(r_x || p_x || m)
        let r_x = r_v.to_affine().x().to_vec();
        let p_x = key.p.to_affine().x().to_vec();
        let e_v = p256::elliptic_curve::ScalarPrimitive::<p256::NistP256>::from_slice(&H::hash(
            [r_x, p_x, message.to_vec()].concat(),
        ));
        // if e_v == e, then the signature is valid\
        e_v.map(p256::Scalar::from)
            .map(|e_v| e_v == signature.e)
            .unwrap_or(false)
    }
}

pub struct PublicKey {
    p: p256::ProjectivePoint,
}

pub struct SigningKey {
    d: p256::NonZeroScalar,
}

pub struct Signature {
    e: p256::Scalar,
    s: p256::Scalar,
}
