use serde::{Deserialize, Serialize};

use crate::Group;

use super::IssueCertificate;

/// Verification request for identification protocol.
#[derive(Clone)]
pub struct VerificationRequest<G: Group> {
    pub(in crate::identification) certificate: IssueCertificate<G>,
    pub(in crate::identification) y: G::P,
}

impl<G: Group> VerificationRequest<G> {
    /// The identity specified in the request.
    #[inline]
    pub fn identity(&self) -> G::P {
        self.certificate.identity()
    }
}

impl<G: Group> Serialize for VerificationRequest<G> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let i = G::serialize_point(&self.certificate.params.i);
        let v = G::serialize_point(&self.certificate.params.v);
        let s = self.certificate.s.clone();
        let y = G::serialize_point(&self.y);
        (i, v, s, y).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for VerificationRequest<G> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (i, v, s, y): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
            Deserialize::deserialize(deserializer)?;
        let i = G::deserialize_point(&i)
            .map_err(|_| serde::de::Error::custom("Invalid point for i"))?;
        let v = G::deserialize_point(&v)
            .map_err(|_| serde::de::Error::custom("Invalid point for v"))?;
        let y = G::deserialize_point(&y)
            .map_err(|_| serde::de::Error::custom("Invalid point for y"))?;
        Ok(VerificationRequest {
            certificate: IssueCertificate {
                params: super::IssueParams { i, v },
                s,
            },
            y,
        })
    }
}

#[test]
fn test_verification_request_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let certificate = IssueCertificate::<crate::group::p256::SchnorrP256Group> {
        params: crate::identification::IssueParams {
            i: group.random_element(rng),
            v: group.random_element(rng),
        },
        s: vec![1, 2, 3], // Example signature
    };
    let request = VerificationRequest::<crate::group::p256::SchnorrP256Group> {
        certificate,
        y: group.random_element(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&request, bincode::config::legacy()).unwrap();
    let (deserialized, _): (VerificationRequest<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(
        request.certificate.params.i,
        deserialized.certificate.params.i
    );
    assert_eq!(request.y, deserialized.y);
}
