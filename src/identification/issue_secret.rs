use serde::{Deserialize, Serialize};

use crate::Group;

/// Issue secret for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueSecret<G: Group> {
    pub(in crate::identification) e: G::F,
}
