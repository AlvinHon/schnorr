use crate::Group;

use super::IssueParams;

/// Issue certificate for identification protocol.
#[derive(Clone)] // TODO implement Serialize and Deserialize
pub struct IssueCertificate<G: Group> {
    pub(in crate::identification) params: IssueParams<G>,
    pub(in crate::identification) s: Vec<u8>,
}
