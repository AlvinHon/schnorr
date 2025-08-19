use serde::{Deserialize, Serialize};

use crate::Group;

/// Verification request secret for identification protocol.
#[derive(Clone)]
pub struct VerificationRequestSecret<G: Group> {
    pub(in crate::identification) k: G::F,
}

impl<G: Group> Serialize for VerificationRequestSecret<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        G::serialize_scalar(&self.k).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for VerificationRequestSecret<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let k: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let k = G::deserialize_scalar(&k)
            .map_err(|_| serde::de::Error::custom("Invalid scalar for k"))?;
        Ok(VerificationRequestSecret { k })
    }
}

#[test]
fn test_verification_request_secret_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let secret = VerificationRequestSecret::<crate::group::p256::SchnorrP256Group> {
        k: group.random_scalar(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&secret, bincode::config::legacy()).unwrap();
    let (deserialized, _): (
        VerificationRequestSecret<crate::group::p256::SchnorrP256Group>,
        _,
    ) = bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(secret.k, deserialized.k);
}
