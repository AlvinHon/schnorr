use serde::{Deserialize, Serialize};

use crate::Group;

use super::IssueParams;

/// Issue certificate for identification protocol.
#[derive(Clone)]
pub struct IssueCertificate<G: Group> {
    pub(in crate::identification) params: IssueParams<G>,
    pub(in crate::identification) s: Vec<u8>,
}

impl<G: Group> IssueCertificate<G> {
    /// The identity specified in the certificate.
    #[inline]
    pub fn identity(&self) -> G::P {
        self.params.identity()
    }
}

impl<G: Group> Serialize for IssueCertificate<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let i = G::serialize_point(&self.params.i);
        let v = G::serialize_point(&self.params.v);
        (i, v, self.s.clone()).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for IssueCertificate<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (i, v, s): (Vec<u8>, Vec<u8>, Vec<u8>) = Deserialize::deserialize(deserializer)?;
        let i = G::deserialize_point(&i)
            .map_err(|_| serde::de::Error::custom("Invalid point for i"))?;
        let v = G::deserialize_point(&v)
            .map_err(|_| serde::de::Error::custom("Invalid point for v"))?;
        Ok(IssueCertificate {
            params: IssueParams { i, v },
            s,
        })
    }
}

#[test]
fn test_issue_certificate_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let params = IssueParams::<crate::group::p256::SchnorrP256Group> {
        i: group.random_element(rng),
        v: group.random_element(rng),
    };
    let certificate = IssueCertificate::<crate::group::p256::SchnorrP256Group> {
        params,
        s: vec![1, 2, 3], // Example signature
    };
    let serialized =
        bincode::serde::encode_to_vec(&certificate, bincode::config::legacy()).unwrap();
    let (deserialized, _): (IssueCertificate<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(certificate.params.i, deserialized.params.i);
    assert_eq!(certificate.s, deserialized.s);
}
