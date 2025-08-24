use serde::{Deserialize, Serialize};

use crate::Group;

/// Signing key for the Schnorr Signature Scheme.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey<G: Group> {
    pub(crate) d: G::F,
}

impl<G: Group> Serialize for SigningKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Vec::<u8>::from(self).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for SigningKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<SigningKey<G>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        SigningKey::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("Invalid signing key"))
    }
}

impl<G: Group> From<&SigningKey<G>> for Vec<u8> {
    fn from(signing_key: &SigningKey<G>) -> Self {
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

#[test]
fn test_signing_key_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let sk = SigningKey::<crate::group::p256::SchnorrP256Group> {
        d: group.random_scalar(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&sk, bincode::config::legacy()).unwrap();
    let (deserialized, _): (SigningKey<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(sk.d, deserialized.d);

    // Test From<&SigningKey> for Vec<u8>
    let sk_bytes: Vec<u8> = (&sk).into();
    let deserialized_from_bytes: SigningKey<crate::group::p256::SchnorrP256Group> =
        SigningKey::try_from(sk_bytes.as_slice()).unwrap();
    assert!(sk == deserialized_from_bytes);
}
