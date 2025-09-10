use serde::{Deserialize, Serialize};

use crate::Group;

/// Issue secret for identification protocol.
#[derive(Clone)]
pub struct IssueSecret<G: Group> {
    pub(in crate::identification) e: G::F,
}

impl<G: Group> Serialize for IssueSecret<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        G::serialize_scalar(&self.e).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for IssueSecret<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let e: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let e = G::deserialize_scalar(&e)
            .map_err(|_| serde::de::Error::custom("Invalid scalar for e"))?;
        Ok(IssueSecret { e })
    }
}

#[test]
fn test_issue_secret_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let secret = IssueSecret::<crate::group::p256::SchnorrP256Group> {
        e: group.random_scalar(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&secret, bincode::config::legacy()).unwrap();
    let (deserialized, _): (IssueSecret<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(secret.e, deserialized.e);
}
