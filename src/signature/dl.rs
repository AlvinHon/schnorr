//! Implementation of Schnorr Signature Scheme (based on discrete logarithm problem)

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{Hash, Rand, SchnorrGroup};

/// Schnorr Signature Scheme based on discrete logarithm problem.
///
/// The scheme consists of the following steps:
/// 1. Generate a key pair (d, p) where p = a^(-d) mod p.
/// 2. Sign a message m with the key pair (d, p) by generating a random number k and calculate r = a^k mod p and e = H(r || p || m).
/// 3. Calculate s = k + e*d mod q.
/// 4. The signature is (s, e).
/// 5. Verify the signature by calculating r_v = a^s * p^e mod p and e_v = H(r || p || m). If e_v == e, then the signature is valid.
///
#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureScheme<H: Hash> {
    group: SchnorrGroup,
    _phantom: std::marker::PhantomData<H>,
}

impl<H: Hash> SignatureScheme<H> {
    /// Create a Schnorr Identification Protocol from string representation of p, q, and a,
    /// which are the parameters of the schnorr group (See the function [SchnorrGroup::from_str]).
    pub fn from_str(p: &str, q: &str, a: &str) -> Option<Self> {
        let group = SchnorrGroup::from_str(p, q, a)?;
        Some(Self {
            group,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Generate a key pair (d, p) where p = a^(-d) mod p.
    /// Return the signing key and public key.
    /// The signing key is used to sign a message (by calling [SignatureScheme::sign]),
    /// while the public key is used to verify the signature (by calling [SignatureScheme::verify]).
    pub fn generate_key<R: Rand>(&self) -> (SigningKey, PublicKey) {
        // p = a^(-d) mod p
        let d = R::random_number(&self.group.q);
        let p = self
            .group
            .a
            .modpow(&d, &self.group.p)
            .modinv(&self.group.p)
            .unwrap();
        (SigningKey { d }, PublicKey { p })
    }

    /// Sign a message m with the key pair (d, p) by generating a random number k and
    /// - calculate r = a^k mod p and e = H(r || p || m).
    /// - calculate s = k + e*d mod q.
    ///
    /// Return the signature (s, e).
    /// The signature is used to verify the message (by calling [SignatureScheme::verify]).
    pub fn sign<R: Rand, M: AsRef<[u8]>>(
        &self,
        key: &SigningKey,
        pub_key: &PublicKey,
        message: M,
    ) -> Signature {
        let k = R::random_number(&self.group.q);
        // r = a^k mod p
        let r = self.group.a.modpow(&k, &self.group.p);
        // e = H(r || p || m) // Modification on original scheme: adding p to prevent existential forgery
        let e = BigUint::from_bytes_le(&H::hash(
            [
                r.to_bytes_le(),
                pub_key.p.to_bytes_le(),
                message.as_ref().to_vec(),
            ]
            .concat(),
        ));
        // s = k + e*d mod q
        let s = &k + &e * &key.d % &self.group.q;
        Signature { s, e }
    }

    /// Verify the signature by calculating r_v = a^s * p^e mod p and e_v = H(r || p || m).
    /// If e_v == e, then the signature is valid.
    /// Return true if the signature is valid, otherwise false.
    pub fn verify(&self, key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        // r_v = a^s * p^e mod p
        let r_v = self.group.a.modpow(&signature.s, &self.group.p)
            * key.p.modpow(&signature.e, &self.group.p)
            % &self.group.p;
        // e_v = H(r || p || m) // Modification on original scheme: adding p to prevent existential forgery
        let e_v = BigUint::from_bytes_le(&H::hash(
            [r_v.to_bytes_le(), key.p.to_bytes_le(), message.to_vec()].concat(),
        ));
        // if e_v == e, then the signature is valid
        e_v == signature.e
    }
}

/// Signing key for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    p: BigUint,
}

impl From<PublicKey> for Vec<u8> {
    fn from(public_key: PublicKey) -> Self {
        let p_bytes = public_key.p.to_bytes_le();
        let p_bytes_len = p_bytes.len();
        [(p_bytes_len as u32).to_le_bytes().to_vec(), p_bytes].concat()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(());
        }

        let p_len = u32::from_le_bytes(value[..4].try_into().unwrap()) as usize;

        if value.len() != 4 + p_len {
            return Err(());
        }

        let p_bytes = &value[4..];
        let p = BigUint::from_bytes_le(p_bytes);
        Ok(PublicKey { p })
    }
}

/// Public key for the Schnorr Signature Scheme.
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKey {
    d: BigUint,
}

impl From<SigningKey> for Vec<u8> {
    fn from(signing_key: SigningKey) -> Self {
        let d_bytes = signing_key.d.to_bytes_le();
        let d_bytes_len = d_bytes.len();
        [(d_bytes_len as u32).to_le_bytes().to_vec(), d_bytes].concat()
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(());
        }

        let d_len = u32::from_le_bytes(value[..4].try_into().unwrap()) as usize;

        if value.len() != 4 + d_len {
            return Err(());
        }

        let d_bytes = &value[4..];
        let d = BigUint::from_bytes_le(d_bytes);
        Ok(SigningKey { d })
    }
}

/// Signature for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Signature {
    s: BigUint,
    e: BigUint,
}

impl From<Signature> for Vec<u8> {
    fn from(signature: Signature) -> Self {
        let s_bytes = signature.s.to_bytes_le();
        let e_bytes = signature.e.to_bytes_le();
        let s_bytes_len = s_bytes.len();
        let e_bytes_len = e_bytes.len();
        [
            (s_bytes_len as u32).to_le_bytes().to_vec(),
            s_bytes,
            (e_bytes_len as u32).to_le_bytes().to_vec(),
            e_bytes,
        ]
        .concat()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(());
        }

        let s_len = u32::from_le_bytes(value[..4].try_into().unwrap()) as usize;

        if value.len() < 8 + s_len {
            return Err(());
        }

        let e_len = u32::from_le_bytes(value[4 + s_len..8 + s_len].try_into().unwrap()) as usize;

        if value.len() != 8 + s_len + e_len {
            return Err(());
        }

        let s_bytes = &value[4..4 + s_len];
        let e_bytes = &value[8 + s_len..];

        let s = BigUint::from_bytes_le(s_bytes);
        let e = BigUint::from_bytes_le(e_bytes);
        Ok(Signature { s, e })
    }
}
