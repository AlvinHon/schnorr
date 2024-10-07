#![doc = include_str!("../README.md")]

use digest::Digest;

pub mod group;
pub use group::{Group, SchnorrGroup, SchnorrP256Group};

pub mod public_key;
pub use public_key::PublicKey;

pub mod signature;
pub use signature::Signature;

pub mod signature_scheme;
pub use signature_scheme::SignatureScheme;

pub mod signing_key;
pub use signing_key::SigningKey;

pub mod signer;
pub use signer::Signer;

pub mod verifier;
pub use verifier::Verifier;

pub mod identification;

/// Instantiate a Schnorr Signature Protocol from string representation of p, q, and a:
/// - p is a large prime
/// - q is a large prime divisor of p-1
/// - a is a generator of the group of order q, i.e., a^q mod p = 1 by Fermat's Little Theorem.
///
/// Return None if a is not a valid generator (i.e. a^q mod p != 1)
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

/// Instantiate a Schnorr Identification Protocol from string representation of p, q, and a:
/// - p is a large prime
/// - q is a large prime divisor of p-1
/// - a is a generator of the group of order q, i.e., a^q mod p = 1 by Fermat's Little Theorem.
///
/// Return None if a is not a valid generator (i.e. a^q mod p != 1)
pub fn identification_protocol(
    p: &str,
    q: &str,
    a: &str,
) -> Option<identification::Identification<SchnorrGroup>> {
    SchnorrGroup::from_str(p, q, a).map(|group| identification::Identification { group })
}

/// Instantiate a Schnorr Signature Protocol based on elliptic curve p256. The generator point is provided by crate [p256].
pub fn signature_scheme_p256<H: Digest>() -> SignatureScheme<SchnorrP256Group, H> {
    let group = SchnorrP256Group;
    SignatureScheme {
        group,
        _phantom: std::marker::PhantomData,
    }
}

/// Instantiate a Schnorr Identification Protocol based on elliptic curve p256. The generator point is provided by crate [p256].
pub fn identificatio_protocol_p256() -> identification::Identification<SchnorrP256Group> {
    identification::Identification {
        group: SchnorrP256Group,
    }
}
