use serde::{Deserialize, Serialize};

use crate::Group;

/// Issue parameters for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueParams<G: Group> {
    pub(in crate::identification) i: G::P,
    pub(in crate::identification) v: G::P,
}
