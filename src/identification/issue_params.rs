use serde::{Deserialize, Serialize};

use crate::Group;

/// Issue parameters for identification protocol.
#[derive(Clone)]
pub struct IssueParams<G: Group> {
    pub(in crate::identification) i: G::P,
    pub(in crate::identification) v: G::P,
}

impl<G: Group> IssueParams<G> {
    /// The identity specified in the parameters.
    #[inline]
    pub fn identity(&self) -> G::P {
        self.i.clone()
    }
}

impl<G: Group> Serialize for IssueParams<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let i = G::serialize_point(&self.i);
        let v = G::serialize_point(&self.v);
        (i, v).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for IssueParams<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (i, v): (Vec<u8>, Vec<u8>) = Deserialize::deserialize(deserializer)?;
        let i = G::deserialize_point(&i)
            .map_err(|_| serde::de::Error::custom("Invalid point for i"))?;
        let v = G::deserialize_point(&v)
            .map_err(|_| serde::de::Error::custom("Invalid point for v"))?;
        Ok(IssueParams { i, v })
    }
}

#[test]
fn test_issue_params_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let params = IssueParams::<crate::group::p256::SchnorrP256Group> {
        i: group.random_element(rng),
        v: group.random_element(rng),
    };

    let serialized = bincode::serde::encode_to_vec(&params, bincode::config::legacy()).unwrap();
    let (deserialized, _): (IssueParams<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();

    assert_eq!(params.i, deserialized.i);
    assert_eq!(params.v, deserialized.v);
}
