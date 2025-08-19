use serde::{Deserialize, Serialize};

use crate::Group;

/// Verification challenge for identification protocol.
#[derive(Clone)]
pub struct VerificationChallenge<G: Group> {
    pub(in crate::identification) r: G::F,
}

impl<G: Group> Serialize for VerificationChallenge<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        G::serialize_scalar(&self.r).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for VerificationChallenge<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let r: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let r = G::deserialize_scalar(&r)
            .map_err(|_| serde::de::Error::custom("Invalid scalar for r"))?;
        Ok(VerificationChallenge { r })
    }
}

#[test]
fn test_verification_challenge_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let challenge = VerificationChallenge::<crate::group::p256::SchnorrP256Group> {
        r: group.random_scalar(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&challenge, bincode::config::legacy()).unwrap();
    let (deserialized, _): (
        VerificationChallenge<crate::group::p256::SchnorrP256Group>,
        _,
    ) = bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(challenge.r, deserialized.r);
}
