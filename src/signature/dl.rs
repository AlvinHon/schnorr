//! Implementation of Schnorr Signature Scheme (based on discrete logarithm problem)

use num_bigint::BigUint;

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
pub struct PublicKey {
    p: BigUint,
}

/// Public key for the Schnorr Signature Scheme.
pub struct SigningKey {
    d: BigUint,
}

/// Signature for the Schnorr Signature Scheme.
pub struct Signature {
    s: BigUint,
    e: BigUint,
}
