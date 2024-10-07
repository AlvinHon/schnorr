use serde::{Deserialize, Serialize};

use crate::Group;

/// Signature for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Signature<G: Group> {
    pub(crate) s: G::F,
    pub(crate) e: G::F,
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
