//! Implementation of Schnorr Signature Scheme (based on discrete logarithm problem)
use digest::Digest;
use serde::{Deserialize, Serialize};

use crate::Group;

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
    pub fn generate_key<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (SigningKey<G>, PublicKey<G>) {
        // p = a^(-d) mod p
        let d = self.group.rand(rng);
        let neg_d = self.group.neg(&d);
        let p = self.group.gmul(&neg_d);
        (SigningKey { d }, PublicKey { p })
    }

    /// Sign a message m with the key pair (d, p) by generating a random number k and
    /// - calculate r = a^k mod p and e = H(r || p || m).
    /// - calculate s = k + e*d mod q.
    ///
    /// Return the signature (s, e).
    /// The signature is used to verify the message (by calling [SignatureScheme::verify]).
    pub fn sign<R: rand::RngCore + rand::CryptoRng, M: AsRef<[u8]>>(
        &self,
        rng: &mut R,
        key: &SigningKey<G>,
        pub_key: &PublicKey<G>,
        message: M,
    ) -> Signature<G> {
        let k = self.group.rand(rng);
        // r = a^k mod p
        let r = self.group.gmul(&k);
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
            let a_s = self.group.gmul(&signature.s);
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
        G::is_equavalent_scalars(&e_v, &signature.e)
    }
}

/// Signing key for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone)]
pub struct PublicKey<G: Group> {
    p: G::P,
}

impl<G: Group> Serialize for PublicKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = Vec::<u8>::from(self);
        bytes.serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for PublicKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<PublicKey<G>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        PublicKey::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("Invalid public key"))
    }
}

impl<G: Group> From<&PublicKey<G>> for Vec<u8> {
    fn from(public_key: &PublicKey<G>) -> Self {
        let p_bytes = G::serialize_point(&public_key.p);
        let p_bytes_len = p_bytes.len();
        [(p_bytes_len as u32).to_le_bytes().to_vec(), p_bytes].concat()
    }
}

impl<G: Group> TryFrom<&[u8]> for PublicKey<G> {
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
        let p = G::deserialize_point(p_bytes);
        Ok(PublicKey { p })
    }
}

/// Public key for the Schnorr Signature Scheme.
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKey<G: Group> {
    d: G::F,
}

impl<G: Group> From<SigningKey<G>> for Vec<u8> {
    fn from(signing_key: SigningKey<G>) -> Self {
        let d_bytes = G::serialize_scalar(&signing_key.d);
        let d_bytes_len = d_bytes.len();
        [(d_bytes_len as u32).to_le_bytes().to_vec(), d_bytes].concat()
    }
}

impl<G: Group> TryFrom<&[u8]> for SigningKey<G> {
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
        let d = G::deserialize_scalar(d_bytes);
        Ok(SigningKey { d })
    }
}

/// Signature for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Signature<G: Group> {
    s: G::F,
    e: G::F,
}

impl<G: Group> From<Signature<G>> for Vec<u8> {
    fn from(signature: Signature<G>) -> Self {
        let s_bytes = G::serialize_scalar(&signature.s);
        let e_bytes = G::serialize_scalar(&signature.e);
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

impl<G: Group> TryFrom<&[u8]> for Signature<G> {
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

        let s = G::deserialize_scalar(s_bytes);
        let e = G::deserialize_scalar(e_bytes);
        Ok(Signature { s, e })
    }
}

pub struct Signer<'a, H, G>
where
    H: Digest,
    G: Group,
{
    pub key: &'a SigningKey<G>,
    pub pub_key: &'a PublicKey<G>,
    pub scheme: &'a SignatureScheme<G, H>,
}

impl<'a, H, G> signature::RandomizedDigestSigner<H, Vec<u8>> for Signer<'a, H, G>
where
    H: Digest,
    G: Group,
{
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl signature::rand_core::CryptoRngCore,
        digest: H,
    ) -> Result<Vec<u8>, signature::Error> {
        let message = digest.finalize();
        Ok(self
            .scheme
            .sign(rng, self.key, self.pub_key, message.as_slice())
            .into())
    }
}

pub struct Verifier<'a, H, G>
where
    H: Digest,
    G: Group,
{
    pub key: &'a PublicKey<G>,
    pub scheme: &'a SignatureScheme<G, H>,
}

impl<'a, H, G, T> signature::DigestVerifier<H, T> for Verifier<'a, H, G>
where
    H: Digest,
    G: Group,
    T: AsRef<[u8]>,
{
    fn verify_digest(&self, digest: H, signature: &T) -> Result<(), signature::Error> {
        let signature =
            Signature::try_from(signature.as_ref()).map_err(|_| signature::Error::new())?;

        let hashed_bytes = digest.finalize();
        self.scheme
            .verify(self.key, &hashed_bytes, &signature)
            .then(|| ())
            .ok_or(signature::Error::new())
    }
}
