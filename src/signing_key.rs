use serde::{Deserialize, Serialize};

use crate::Group;

/// Public key for the Schnorr Signature Scheme.
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKey<G: Group> {
    pub(crate) d: G::F,
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
        let d = G::deserialize_scalar(d_bytes).map_err(|_| ())?;
        Ok(SigningKey { d })
    }
}
