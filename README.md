# Schnorr Protocols

This repository contains the rust implementation of various Schnorr protocols by Dr. [Claus-Peter Schnorr](https://en.wikipedia.org/wiki/Claus_P._Schnorr):
- Schnorr Identification Protocol
- Schnorr Signature Scheme
- A variant of Schnorr Signature Scheme (elliptic curve cryptograhy based)

It is a light-weight library that implements the protocol in simpliest way where minimal number of APIs are used, though the protocols are highly interactive.
While there are some limitations for you to consider before using it:
- Uses [dashu](https://crates.io/crates/dashu).
- when using ECC-based protocol, the library picks the curve [p256](https://crates.io/crates/p256) (a.k.a `secp256r1`, `prime256v1`) to use.

Note: this repository has not been thoroughly audited. Please take your own risk if you use it in production environment.

## Schnorr Signature Scheme

```rust
// Specify the common parameters from Integer field elements. (Not provided by this crate)
let scheme = schnorr_rs::signature_scheme::<sha2::Sha256>("1623299", "811649", "1109409").unwrap();

let rng = &mut rand::thread_rng();

let (key, public_key) = scheme.generate_key(rng);
let message = "hello world".as_bytes();
let signature = scheme.sign(rng, &key, &public_key, message);
assert!(scheme.verify(&public_key, message, &signature));
```

For the ECC-based scheme, use method `schnorr_rs::signature_scheme_p256` to instantiate the scheme.


## Schnorr Identification Protocol

The protocol involves `user`, `issuer` and `verifier`, who share the same parameters defined in the struct `Identification`. 

In following example, `i` is the identify in type `BigUInt`.

```rust
// Specify the common parameters from Integer field elements. (Not provided by this crate)
let protocol = schnorr_rs::identification_protocol("1623299", "811649", "1109409").unwrap();

let rng = &mut rand::thread_rng();

// Specify the signature scheme used in the protocol. It is not a must to use the scheme provided
// by this crate, as long as the signer and verifier implements the trait `signature::RandomizedDigestSigner`
// and `signature::DigestVerifier` respectively.
let signature_scheme = schnorr_rs::signature_scheme::<sha2::Sha256>("1623299", "811649", "1109409").unwrap();
let (signing_key, public_key) = signature_scheme.generate_key(rng);
let signer = schnorr_rs::Signer {
    scheme: &signature_scheme,
    key: &signing_key,
    pub_key: &public_key,
};
let verifier = schnorr_rs::Verifier {
    scheme: &signature_scheme,
    key: &public_key,
};

// An identity represented by BigUint.
let i = dashu::integer::UBig::from(123u32);

// User interacts with issuer to get a certificate
let (iss_secret, iss_params) = protocol.issue_params(rng, i.clone());
let cert = protocol.issue_certificate(rng, &signer, iss_params);

// User presents the certificate to the verifier
let (ver_secret, ver_req) = protocol.verification_request(rng, cert);

// Verifier challenges the user's knowledge of the secret
let challenge = protocol
    .verification_challenge(rng, &verifier, ver_req.clone())
    .unwrap();

// User responds to the challenge
let ver_res = protocol.verification_response(challenge.clone(), iss_secret, ver_secret);

// Verifier verifies the response
assert!(protocol.verification(ver_req, challenge, ver_res));
```

For the ECC-based protocol, use method `schnorr_rs::identification_protocol_p256` to instantiate the protocol.