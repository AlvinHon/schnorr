//! Implementation of Schnorr Identification Protocol.

pub mod issue_secret;
pub use issue_secret::IssueSecret;

pub mod issue_params;
pub use issue_params::IssueParams;

pub mod issue_certificate;
pub use issue_certificate::IssueCertificate;

pub mod ver_req_secret;
pub use ver_req_secret::VerificationRequestSecret;

pub mod ver_req;
pub use ver_req::VerificationRequest;

pub mod ver_challenge;
pub use ver_challenge::VerificationChallenge;

pub mod ver_response;
pub use ver_response::VerificationResponse;

use crate::Group;
use digest::Digest;
use serde::{Deserialize, Serialize};

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
pub struct Identification<G: Group> {
    pub(crate) group: G,
}

impl<G: Group> Identification<G> {
    /// Issue parameters for identification protocol.
    /// Generate a random number e and calculate v = a^(-e) mod p.
    /// Return the issue secret and issue parameters.
    /// The issue secret is used to calculate the verification response (by calling [Identification::verification_response]),
    /// while the issue parameters are used to create a certificate (by calling [Identification::issue_certificate]).
    pub fn issue_params<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        i: G::P,
    ) -> (IssueSecret<G>, IssueParams<G>) {
        let e = self.group.rand(rng);
        let neg_e = self.group.neg(&e);
        // v = a^(-e) mod p
        let v = self.group.gmul(&neg_e);
        (IssueSecret { e }, IssueParams { i, v })
    }

    /// Issue a certificate for the identification protocol.
    /// Sign the hash of the concatenation of i and v.
    /// Return the issue certificate.
    /// The issue certificate is used to create a verification request (by calling [Identification::verification_request]).
    pub fn issue_certificate<R, H, Sig>(
        &self,
        rng: &mut R,
        signature_scheme: &Sig,
        params: IssueParams<G>,
    ) -> IssueCertificate<G>
    where
        R: rand::CryptoRng + rand::RngCore,
        H: Digest,
        Sig: signature::RandomizedDigestSigner<H, Vec<u8>>,
    {
        // s = sign(H(i || v))
        let digest =
            H::new().chain_update([G::map_point(&params.i), G::map_point(&params.v)].concat());
        let s = signature_scheme.sign_digest_with_rng(rng, digest);

        IssueCertificate { params, s }
    }

    /// Create a verification request for the identification protocol.
    /// Generate a random number k and calculate y = a^k mod p.
    /// Return the verification request secret and the verification request.
    /// The verification request secret is used to calculate the verification response (by calling [Identification::verification_response]),
    /// while the verification request is used to create a verification challenge (by calling [Identification::verification_challenge]).
    pub fn verification_request<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
        certificate: IssueCertificate<G>,
    ) -> (VerificationRequestSecret<G>, VerificationRequest<G>) {
        let k = self.group.rand(rng);
        // y = a^k mod p
        let y = self.group.gmul(&k);

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
    pub fn verification_challenge<R, H, Ver>(
        &self,
        rng: &mut R,
        signature_scheme: &Ver,
        request: VerificationRequest<G>,
    ) -> Option<VerificationChallenge<G>>
    where
        R: rand::CryptoRng + rand::RngCore,
        H: Digest,
        Ver: signature::DigestVerifier<H, Vec<u8>>,
    {
        // verify signature: s == sign(H(i || v))
        let digest = H::new().chain_update(
            [
                G::map_point(&request.certificate.params.i),
                G::map_point(&request.certificate.params.v),
            ]
            .concat(),
        );
        signature_scheme
            .verify_digest(digest, &request.certificate.s)
            .ok()
            .map(|_| VerificationChallenge {
                r: self.group.rand(rng),
            })
    }

    /// Create a verification response for the identification protocol.
    /// Calculate p = k + r * e mod q.
    /// Return the verification response. The verification response is used to verify the identification
    /// (by calling [Identification::verification]).
    pub fn verification_response(
        &self,
        challenge: VerificationChallenge<G>,
        iss_secret: IssueSecret<G>,
        ver_secret: VerificationRequestSecret<G>,
    ) -> VerificationResponse<G> {
        // p = k + r * e mod q
        VerificationResponse {
            p: self
                .group
                .add_mul_scalar(&ver_secret.k, &challenge.r, &iss_secret.e),
        }
    }

    /// Verify the signature of the certificate.
    /// Verify if y == a^p * v^r mod p.
    /// Return true if the identification is valid.
    /// The identification is valid if y == a^p * v^r mod p.
    pub fn verification(
        &self,
        request: VerificationRequest<G>,
        challenge: VerificationChallenge<G>,
        response: VerificationResponse<G>,
    ) -> bool {
        // y == a^p * v^r mod p
        let lhs = {
            let a_p = self.group.gmul(&response.p);
            let v_r = self.group.mul(&request.certificate.params.v, &challenge.r);
            self.group.dot(&a_p, &v_r)
        };
        let rhs = request.y;
        G::is_equavalent_points(&lhs, &rhs)
    }
}
