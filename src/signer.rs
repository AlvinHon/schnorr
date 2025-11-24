use digest::Digest;

use crate::{Group, PublicKey, SignatureScheme, SigningKey};

/// Implements the [signature::RandomizedDigestSigner] trait for a given signature scheme.
/// It is used by [Identification](crate::Identification) in steps that need to sign a hashed message.
pub struct Signer<'a, H, G>
where
    H: Digest,
    G: Group,
{
    pub key: &'a SigningKey<G>,
    pub pub_key: &'a PublicKey<G>,
    pub scheme: &'a SignatureScheme<G, H>,
}

impl<H, G> signature::RandomizedDigestSigner<H, Vec<u8>> for Signer<'_, H, G>
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
        Ok(Vec::<u8>::from(&self.scheme.sign(
            rng,
            self.key,
            self.pub_key,
            &message,
        )))
    }
}

#[test]
fn test_signer_try_sign_digest_with_rng() {
    use sha2::Sha256;
    use signature::RandomizedDigestSigner;

    let scheme = crate::signature_scheme_p256::<Sha256>();

    let rng = &mut rand::thread_rng();
    let (signing_key, public_key) = scheme.generate_key(rng);

    let signer = Signer {
        key: &signing_key,
        pub_key: &public_key,
        scheme: &scheme,
    };

    let message = b"Test message for signing";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest = hasher;

    let signature_bytes = signer
        .try_sign_digest_with_rng(rng, digest.clone())
        .expect("Signing failed");
    let signature =
        crate::Signature::try_from(signature_bytes.as_slice()).expect("Failed to parse signature");

    // verify the signature using the digest
    let digest = digest.finalize();
    assert!(scheme.verify(&public_key, &digest, &signature));
}
