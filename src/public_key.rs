use serde::{Deserialize, Serialize};

use crate::Group;

/// Signing key for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone)]
pub struct PublicKey<G: Group> {
    pub(crate) p: G::P,
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
