use tracing::{info, warn};
use serde::{Deserialize, Serialize};
use agent_mesh_core::identity::agent_id::PrivilegeRing;

pub struct Enforcer;

#[derive(Debug, Serialize, Deserialize)]
pub struct DenyEvent {
    pub agent_did: String,
    pub agent_ring: PrivilegeRing,
    pub required_ring: PrivilegeRing,
    pub action: String,
}

impl Enforcer {
    pub fn can_execute(
        agent_did: &str,
        agent_ring: PrivilegeRing,
        required_ring: PrivilegeRing,
        action: &str,
    ) -> bool {
        if agent_ring <= required_ring {
            info!(
                agent_did = agent_did,
                action = action,
                "Action permitted: {:?} <= {:?}",
                agent_ring,
                required_ring
            );
            true
        } else {
            let event = DenyEvent {
                agent_did: agent_did.to_string(),
                agent_ring,
                required_ring,
                action: action.to_string(),
            };
            warn!(
                deny_event = ?event,
                "Action denied"
            );
            false
        }
    }
}
