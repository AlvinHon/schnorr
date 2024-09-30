//! Implementation of Schnorr Identification Protocol

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{Hash, Identity, Rand, SchnorrGroup, SignatureInIdentification};

/// Schnorr Identification Protocol implementation with generic hash and signature schemes.
///
/// The protocol consists of the following steps:
/// 1. Issue parameters: Generate a random number e and calculate v = a^(-e) mod p.
/// 2. Issue certificate: Sign the hash of the concatenation of i and v.
/// 3. Verification request: Generate a random number k and calculate y = a^k mod p.
/// 4. Verification challenge: Verify the signature of the certificate. If the signature is valid, generate a random number r.
/// 5. Verification response: Calculate p = k + r * e mod q.
/// 6. Verification: Verify if y == a^p * v^r mod p.
#[derive(Clone, Serialize, Deserialize)]
pub struct Identification<H: Hash, S: SignatureInIdentification>
where
    S: SignatureInIdentification,
    H: Hash,
{
    group: SchnorrGroup,
    _phantom: std::marker::PhantomData<(H, S)>,
}

impl<H, S> Identification<H, S>
where
    S: SignatureInIdentification,
    H: Hash,
{
    /// Create a Schnorr Identification Protocol from string representation of p, q, and a,
    /// which are the parameters of the schnorr group (See the function [SchnorrGroup::from_str]).
    pub fn from_str(p: &str, q: &str, a: &str) -> Option<Self> {
        let group = SchnorrGroup::from_str(p, q, a)?;
        Some(Self {
            group,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Issue parameters for identification protocol.
    /// Generate a random number e and calculate v = a^(-e) mod p.
    /// Return the issue secret and issue parameters.
    /// The issue secret is used to calculate the verification response (by calling [Identification::verification_response]),
    /// while the issue parameters are used to create a certificate (by calling [Identification::issue_certificate]).
    pub fn issue_params<R: Rand>(&self, i: Identity) -> (IssueSecret, IssueParams) {
        let e = R::random_number(&self.group.q);
        // v = a^(-e) mod p
        let v = self
            .group
            .a
            .modpow(&e, &self.group.p)
            .modinv(&self.group.p)
            .unwrap();
        (IssueSecret { e }, IssueParams { i, v })
    }

    /// Issue a certificate for the identification protocol.
    /// Sign the hash of the concatenation of i and v.
    /// Return the issue certificate.
    /// The issue certificate is used to create a verification request (by calling [Identification::verification_request]).
    pub fn issue_certificate(
        &self,
        signature_scheme: &S,
        issue_params: IssueParams,
    ) -> IssueCertificate {
        // s = sign(H(i || v))
        let s = signature_scheme.sign(H::hash(
            [issue_params.i.to_bytes_le(), issue_params.v.to_bytes_le()].concat(),
        ));

        IssueCertificate {
            params: issue_params,
            s,
        }
    }

    /// Create a verification request for the identification protocol.
    /// Generate a random number k and calculate y = a^k mod p.
    /// Return the verification request secret and the verification request.
    /// The verification request secret is used to calculate the verification response (by calling [Identification::verification_response]),
    /// while the verification request is used to create a verification challenge (by calling [Identification::verification_challenge]).
    pub fn verification_request<R: Rand>(
        &self,
        certificate: IssueCertificate,
    ) -> (VerificationRequestSecret, VerificationRequest) {
        let k = R::random_number(&self.group.q);
        // y = a^k mod p
        let y = self.group.a.modpow(&k, &self.group.p);

        (
            VerificationRequestSecret { k },
            VerificationRequest { certificate, y },
        )
    }

    /// Create a verification challenge for the identification protocol.
    /// Verify the signature of the certificate. If the signature is valid, generate a random number r.
    /// Return the verification challenge. The verification challenge is used to create a verification response
    /// (by calling [Identification::verification_response]).
    /// Return None if the signature is invalid.
    /// The verification challenge is used to create a verification response (by calling [Identification::verification_response]).
    pub fn verification_challenge<R: Rand>(
        &self,
        signature_scheme: &S,
        request: VerificationRequest,
    ) -> Option<VerificationChallenge> {
        // verify signature: s == sign(H(i || v))
        if !signature_scheme.verify(
            H::hash(
                [
                    request.certificate.params.i.to_bytes_le(),
                    request.certificate.params.v.to_bytes_le(),
                ]
                .concat(),
            ),
            &request.certificate.s,
        ) {
            return None;
        }

        Some(VerificationChallenge {
            r: R::random_number(&self.group.q),
        })
    }

    /// Create a verification response for the identification protocol.
    /// Calculate p = k + r * e mod q.
    /// Return the verification response. The verification response is used to verify the identification
    /// (by calling [Identification::verification]).
    pub fn verification_response(
        &self,
        challenge: VerificationChallenge,
        iss_secret: IssueSecret,
        ver_secret: VerificationRequestSecret,
    ) -> VerificationResponse {
        // p = k + r * e mod q
        VerificationResponse {
            p: (&ver_secret.k + &(&challenge.r * &iss_secret.e)) % &self.group.q,
        }
    }

    /// Verify the signature of the certificate.
    /// Verify if y == a^p * v^r mod p.
    /// Return true if the identification is valid.
    /// The identification is valid if y == a^p * v^r mod p.
    pub fn verification(
        &self,
        request: VerificationRequest,
        challenge: VerificationChallenge,
        response: VerificationResponse,
    ) -> bool {
        // y == a^p * v^r mod p
        let lhs = (&self.group.a.modpow(&response.p, &self.group.p)
            * request
                .certificate
                .params
                .v
                .modpow(&challenge.r, &self.group.p))
            % &self.group.p;
        let rhs = request.y;
        lhs == rhs
    }
}

/// Issue secret for identification protocol.
pub struct IssueSecret {
    e: BigUint,
}

/// Issue parameters for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueParams {
    i: Identity,
    v: BigUint,
}

/// Issue certificate for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueCertificate {
    params: IssueParams,
    s: Vec<u8>,
}

/// Verification request secret for identification protocol.
pub struct VerificationRequestSecret {
    k: BigUint,
}

/// Verification request for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    certificate: IssueCertificate,
    y: BigUint,
}

/// Verification challenge for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationChallenge {
    r: BigUint,
}

/// Verification response for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    p: BigUint,
}
