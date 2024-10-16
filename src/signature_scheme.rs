//! Implementation of Schnorr Signature Scheme

use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{Group, PublicKey, Signature, SigningKey};

/// Schnorr Signature Scheme based on discrete logarithm problem.
///
/// The scheme consists of the following steps:
/// 1. Generate a key pair (d, p) where p = a^(-d) mod p.
/// 2. Sign a message m with the key pair (d, p) by generating a random number k and calculate r = a^k mod p and e = H(r || p || m).
/// 3. Calculate s = k + e*d mod q.
/// 4. The signature is (s, e).
/// 5. Verify the signature by calculating r_v = a^s * p^e mod p and e_v = H(r || p || m). If e_v == e, then the signature is valid.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureScheme<G: Group, H: Digest> {
    pub(crate) group: G,
    pub(crate) _phantom: std::marker::PhantomData<H>,
}

impl<G, H> SignatureScheme<G, H>
where
    G: Group,
    H: Digest,
{
    /// Generate a key pair (d, p) where p = a^(-d) mod p.
    /// Return the signing key and public key.
    /// The signing key is used to sign a message (by calling [SignatureScheme::sign]),
    /// while the public key is used to verify the signature (by calling [SignatureScheme::verify]).
    pub fn generate_key<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (SigningKey<G>, PublicKey<G>) {
        // p = a^(-d) mod p
        let d = self.group.rand(rng);
        let neg_d = self.group.neg(&d);
        let p = self.group.mul_by_generator(&neg_d);
        (SigningKey { d }, PublicKey { p })
    }

    /// Sign a message m with the key pair (d, p) by generating a random number k and
    /// - calculate r = a^k mod p and e = H(r || p || m).
    /// - calculate s = k + e*d mod q.
    ///
    /// Return the signature (s, e).
    /// The signature is used to verify the message (by calling [SignatureScheme::verify]).
    pub fn sign<R: RngCore + CryptoRng, M: AsRef<[u8]>>(
        &self,
        rng: &mut R,
        key: &SigningKey<G>,
        pub_key: &PublicKey<G>,
        message: M,
    ) -> Signature<G> {
        let k = self.group.rand(rng);
        // r = a^k mod p
        let r = self.group.mul_by_generator(&k);
        // e = H(r || p || m) // Modification on original scheme: adding p to prevent existential forgery
        let e = G::map_to_scalar(
            H::new()
                .chain_update(
                    [
                        G::map_point(&r),
                        G::map_point(&pub_key.p),
                        message.as_ref().to_vec(),
                    ]
                    .concat(),
                )
                .finalize()
                .as_ref(),
        );
        // s = k + e*d mod q
        let s = self.group.add_mul_scalar(&k, &e, &key.d);
        Signature { s, e }
    }

    /// Verify the signature by calculating r_v = a^s * p^e mod p and e_v = H(r || p || m).
    /// If e_v == e, then the signature is valid.
    /// Return true if the signature is valid, otherwise false.
    pub fn verify(&self, key: &PublicKey<G>, message: &[u8], signature: &Signature<G>) -> bool {
        // r_v = a^s * p^e mod p
        let r_v = {
            let a_s = self.group.mul_by_generator(&signature.s);
            let p_e = self.group.mul(&key.p, &signature.e);
            self.group.dot(&a_s, &p_e)
        };
        // e_v = H(r || p || m) // Modification on original scheme: adding p to prevent existential forgery
        let e_v = G::map_to_scalar(
            H::new()
                .chain_update([G::map_point(&r_v), G::map_point(&key.p), message.to_vec()].concat())
                .finalize()
                .as_ref(),
        );
        // if e_v == e, then the signature is valid
        G::is_equivalent_scalars(&e_v, &signature.e)
    }
}
