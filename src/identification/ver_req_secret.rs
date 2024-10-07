use serde::{Deserialize, Serialize};

use crate::Group;

/// Verification request secret for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationRequestSecret<G: Group> {
    pub(in crate::identification) k: G::F,
}
