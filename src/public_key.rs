use serde::{Deserialize, Serialize};

use crate::Group;

/// Public key for the Schnorr Signature Scheme.
#[derive(PartialEq, Eq, Clone)]
pub struct PublicKey<G: Group> {
    pub(crate) p: G::P,
}

impl<G: Group> PublicKey<G> {
    /// The only group element that represents the public key.
    /// It is basically the p from the key pair (d, p) where p = a^(-d) mod P.
    #[inline]
    pub fn element(&self) -> &G::P {
        &self.p
    }
}

impl<G: Group> Serialize for PublicKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Vec::<u8>::from(self).serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for PublicKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<PublicKey<G>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        PublicKey::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("Invalid public key"))
    }
}

impl<G: Group> From<&PublicKey<G>> for Vec<u8> {
    fn from(public_key: &PublicKey<G>) -> Self {
        G::serialize_point(&public_key.p)
    }
}

impl<G: Group> TryFrom<&[u8]> for PublicKey<G> {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let p = G::deserialize_point(value).map_err(|_| ())?;
        Ok(PublicKey { p })
    }
}

#[test]
fn test_public_key_serialization() {
    let rng = &mut rand::thread_rng();
    let group = crate::group::p256::SchnorrP256Group;
    let pk = PublicKey::<crate::group::p256::SchnorrP256Group> {
        p: group.random_element(rng),
    };
    let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::legacy()).unwrap();
    let (deserialized, _): (PublicKey<crate::group::p256::SchnorrP256Group>, _) =
        bincode::serde::decode_from_slice(&serialized, bincode::config::legacy()).unwrap();
    assert_eq!(pk.p, deserialized.p);

    // Test From<&PublicKey> for Vec<u8>
    let pk_bytes: Vec<u8> = (&pk).into();
    let deserialized_from_bytes: PublicKey<crate::group::p256::SchnorrP256Group> =
        PublicKey::try_from(pk_bytes.as_slice()).unwrap();
    assert!(pk == deserialized_from_bytes);
}
