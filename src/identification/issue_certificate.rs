use serde::{Deserialize, Serialize};

use crate::Group;

use super::IssueParams;

/// Issue certificate for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueCertificate<G: Group> {
    pub(in crate::identification) params: IssueParams<G>,
    pub(in crate::identification) s: Vec<u8>,
}

impl<G: Group> IssueCertificate<G> {
    /// The identity specified in the certificate.
    pub fn identity(&self) -> G::P {
        self.params.i.clone()
    }
}
