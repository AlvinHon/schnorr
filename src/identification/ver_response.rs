use serde::{Deserialize, Serialize};

use crate::Group;

/// Verification response for identification protocol.
#[derive(Clone)]
pub struct VerificationResponse<G: Group> {
    pub(in crate::identification) p: G::F,
}

impl<G: Group> Serialize for VerificationResponse<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        G::serialize_scalar(&self.p).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for VerificationResponse<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let p: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let p = G::deserialize_scalar(&p)
            .map_err(|_| serde::de::Error::custom("Invalid scalar for p"))?;
        Ok(VerificationResponse { p })
    }
}

#[test]
fn test_verification_response_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let response = VerificationResponse::<crate::group::p256::SchnorrP256Group> {
        p: group.random_scalar(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&response, bincode::config::legacy()).unwrap();
    let (deserialized, _): (
        VerificationResponse<crate::group::p256::SchnorrP256Group>,
        _,
    ) = bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(response.p, deserialized.p);
}
