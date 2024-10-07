use serde::{Deserialize, Serialize};

use crate::Group;

/// Verification response for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationResponse<G: Group> {
    pub(in crate::identification) p: G::F,
}
