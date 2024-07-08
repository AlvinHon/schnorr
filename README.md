# Schnorr Protocols

This repository contains the rust implementation of various Schnorr protocols by Dr. [Claus-Peter Schnorr](https://en.wikipedia.org/wiki/Claus_P._Schnorr):
- Schnorr Identification Protocol
- Schnorr Signature Scheme
- A variant of Schnorr Signature Scheme (elliptic curve cryptograhy based)

It is a light-weight library that implements the protocol in simpliest way where minimal number of APIs are used, though the protocols are highly interactive.
While there are some limitations for you to consider before using it:
- Uses [num-bigint](https://crates.io/crates/num-bigint).
- when using ECC-based protocol, the library picks the curve [p256](https://crates.io/crates/p256) (a.k.a `secp256r1`, `prime256v1`) to use.

Welcome to contribute to remove (any) limitations (e.g. to make it more flexible) while keeping the prinicple of simplicity.

## Schnorr Identification Protocol

The protocol involves `user`, `issuer` and `verifier`, who share the same parameters that can be instantiated by `Identification::<Hash>::from_str`. In following example, the variable `schnorr` is its instantiation while `i` is the identify in type `BigUInt`.

```rust
// user interacts with issuer to get a certificate
let (iss_secret, iss_params) = schnorr.issue_params::<Rand>(i.clone());
let cert = schnorr.issue_certificate(iss_params);

// user presents the certificate to the verifier
let (ver_secret, ver_req) = schnorr.verification_request::<Rand>(cert);
// verifier challenges the user's knowledge of the secret
let challenge = schnorr
    .verification_challenge::<Rand>(ver_req.clone())
    .unwrap();
// user responds to the challenge
let ver_res = schnorr.verification_response(challenge.clone(), iss_secret, ver_secret);
// verifier verifies the response
assert!(schnorr.verification(ver_req, challenge, ver_res));
```

## Schnorr Signature Scheme

The scheme starts with the struct `SignatureScheme<Hash>`. It can be instantiated by method `from_str`. In following example, the variable `schnorr` is its instantiation.

```rust
let (key, public_key) = scheme.generate_key::<Rand>();
let message = "hello world".as_bytes();
let signature = scheme.sign::<Rand, _>(&key, &public_key, message);
assert!(scheme.verify(&public_key, message, &signature));
```

For the ECC-based scheme, use struct `SignatureSchemeECP256` which is instantiated by `new` or `default` (because the generator used is fixed).

