use crate::Group;

use super::IssueCertificate;

/// Verification request for identification protocol.
#[derive(Clone)] // TODO implement Serialize and Deserialize
pub struct VerificationRequest<G: Group> {
    pub(in crate::identification) certificate: IssueCertificate<G>,
    pub(in crate::identification) y: G::P,
}
