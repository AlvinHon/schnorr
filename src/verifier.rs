use digest::Digest;

use crate::{Group, PublicKey, Signature, SignatureScheme};

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
