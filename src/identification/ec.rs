//! Implementation of Schnorr Identification Protocol based on elliptic curve cryptography.

use p256::elliptic_curve::{point::AffineCoordinates, Group};

use serde::{Deserialize, Serialize};

use crate::{Hash, SignatureInIdentification};
use std::ops::{Mul, Neg};

/// Schnorr Identification Protocol implementation with generic hash and signature schemes.
///
/// The protocol consists of the following steps:
/// 1. Issue parameters: Generate a random number e and calculate V = (-e)G
/// 2. Issue certificate: Sign the hash of the concatenation of i and V.
/// 3. Verification request: Generate a random number k and calculate Y = kG.
/// 4. Verification challenge: Verify the signature of the certificate. If the signature is valid, generate a random number r.
/// 5. Verification response: Calculate p = k + r * e.
/// 6. Verification: Verify if y == pG + rV.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Identification<H: Hash, S: SignatureInIdentification>
where
    S: SignatureInIdentification,
    H: Hash,
{
    /// generator point
    g: p256::AffinePoint,
    _phantom: std::marker::PhantomData<(H, S)>,
}

impl<H, S> Identification<H, S>
where
    S: SignatureInIdentification,
    H: Hash,
{
    pub fn new() -> Self {
        Self {
            g: p256::ProjectivePoint::generator().to_affine(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Issue parameters for identification protocol.
    /// Generate a random number e and calculate v = (-e)G.
    /// Return the issue secret and issue parameters.
    /// The issue secret is used to calculate the verification response (by calling [Identification::verification_response]),
    /// while the issue parameters are used to create a certificate (by calling [Identification::issue_certificate]).
    pub fn issue_params<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        i: p256::AffinePoint,
    ) -> (IssueSecret, IssueParams) {
        let e = p256::NonZeroScalar::random(rng);
        // V = (-e)G
        let v = self.g.mul(e.neg().as_ref()).to_affine();
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
        // s = sign(H(i_x || v_x))
        let s = signature_scheme.sign(H::hash(
            [issue_params.i.x().to_vec(), issue_params.v.x().to_vec()].concat(),
        ));

        IssueCertificate {
            params: issue_params,
            s,
        }
    }

    /// Create a verification request for the identification protocol.
    /// Generate a random number k and calculate y = kG.
    /// Return the verification request secret and the verification request.
    /// The verification request secret is used to calculate the verification response (by calling [Identification::verification_response]),
    /// while the verification request is used to create a verification challenge (by calling [Identification::verification_challenge]).
    pub fn verification_request<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        certificate: IssueCertificate,
    ) -> (VerificationRequestSecret, VerificationRequest) {
        let k = p256::NonZeroScalar::random(rng);
        // y = kG
        let y = self.g.mul(k.as_ref()).to_affine();
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
    pub fn verification_challenge<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        signature_scheme: &S,
        request: VerificationRequest,
    ) -> Option<VerificationChallenge> {
        // verify signature: s == sign(H(i || v))
        if !signature_scheme.verify(
            H::hash(
                [
                    request.certificate.params.i.x().to_vec(),
                    request.certificate.params.v.x().to_vec(),
                ]
                .concat(),
            ),
            &request.certificate.s,
        ) {
            return None;
        }

        Some(VerificationChallenge {
            r: p256::NonZeroScalar::random(rng),
        })
    }

    /// Create a verification response for the identification protocol.
    /// Calculate p = k + r * e.
    /// Return the verification response. The verification response is used to verify the identification
    /// (by calling [Identification::verification]).
    pub fn verification_response(
        &self,
        challenge: VerificationChallenge,
        iss_secret: IssueSecret,
        ver_secret: VerificationRequestSecret,
    ) -> Option<VerificationResponse> {
        // p = k + r * e
        let p = ver_secret.k.add(&challenge.r.multiply(&iss_secret.e));
        p256::NonZeroScalar::new(p)
            .into_option()
            .map(|p| VerificationResponse { p })
    }

    /// Verify the signature of the certificate.
    /// Verify if Y == pG + rV.
    /// Return true if the identification is valid.
    /// The identification is valid if Y == pG + rV.
    pub fn verification(
        &self,
        request: VerificationRequest,
        challenge: VerificationChallenge,
        response: VerificationResponse,
    ) -> bool {
        // Y == pG + rV
        let y = request.y;
        let p = response.p;
        let v = request.certificate.params.v;
        let r = challenge.r;
        let p_g = self.g.mul(p.as_ref());
        let r_v = v.mul(r.as_ref());
        (p_g + r_v).to_affine() == y
    }
}

/// Issue secret for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueSecret {
    e: p256::NonZeroScalar,
}

/// Issue parameters for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueParams {
    i: p256::AffinePoint,
    v: p256::AffinePoint,
}

/// Issue certificate for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueCertificate {
    params: IssueParams,
    s: Vec<u8>,
}

/// Verification request secret for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationRequestSecret {
    k: p256::NonZeroScalar,
}

/// Verification request for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    certificate: IssueCertificate,
    y: p256::AffinePoint,
}

/// Verification challenge for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationChallenge {
    r: p256::NonZeroScalar,
}

/// Verification response for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    p: p256::NonZeroScalar,
}
