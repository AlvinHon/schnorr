use digest::Digest;

use crate::{Group, PublicKey, SignatureScheme, SigningKey};

/// Implements the [signature::RandomizedDigestSigner] trait for a given signature scheme.
/// It is used by [Identification](crate::Identification) in steps that need to sign a signature.
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
        Ok(self
            .scheme
            .sign(rng, self.key, self.pub_key, message.as_slice())
            .into())
    }
}
