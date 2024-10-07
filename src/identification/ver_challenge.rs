use serde::{Deserialize, Serialize};

use crate::Group;

/// Verification challenge for identification protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerificationChallenge<G: Group> {
    pub(in crate::identification) r: G::F,
}
