use serde::{Deserialize, Serialize};

use crate::Group;

/// Signature for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone)]
pub struct Signature<G: Group> {
    pub(crate) s: G::F,
    pub(crate) e: G::F,
}

impl<G: Group> Serialize for Signature<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Vec::<u8>::from(self).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for Signature<G> {
    fn deserialize<D>(deserializer: D) -> Result<Signature<G>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Signature::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("Invalid signature"))
    }
}

impl<G: Group> From<&Signature<G>> for Vec<u8> {
    fn from(signature: &Signature<G>) -> Self {
        let s_bytes = G::serialize_scalar(&signature.s);
        let e_bytes = G::serialize_scalar(&signature.e);
        [
            (s_bytes.len() as u32).to_le_bytes().to_vec(),
            s_bytes,
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
        let s_len = u32::from_le_bytes(value[0..4].try_into().map_err(|_| ())?) as usize;
        if value.len() < 4 + s_len {
            return Err(());
        }
        let s_bytes = &value[4..4 + s_len];
        let e_bytes = &value[4 + s_len..];
        let s = G::deserialize_scalar(s_bytes).map_err(|_| ())?;
        let e = G::deserialize_scalar(e_bytes).map_err(|_| ())?;
        Ok(Signature { s, e })
    }
}

#[test]
fn test_signature_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let signature = Signature::<crate::group::p256::SchnorrP256Group> {
        s: group.random_scalar(rng),
        e: group.random_scalar(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&signature, bincode::config::legacy()).unwrap();
    let (deserialized, _): (Signature<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert!(signature == deserialized);

    // Test From<&Signature> for Vec<u8>
    let sig_bytes: Vec<u8> = (&signature).into();
    let deserialized_from_bytes: Signature<crate::group::p256::SchnorrP256Group> =
        Signature::try_from(sig_bytes.as_slice()).unwrap();
    assert!(signature == deserialized_from_bytes);
}
