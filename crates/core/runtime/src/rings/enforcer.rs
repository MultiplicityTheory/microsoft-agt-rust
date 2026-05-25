use tracing::{info, warn};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivilegeRing {
    System = 0,
    Trusted = 1,
    Standard = 2,
    Sandboxed = 3,
}

impl FromStr for PrivilegeRing {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "system" => Ok(PrivilegeRing::System),
            "trusted" => Ok(PrivilegeRing::Trusted),
            "standard" => Ok(PrivilegeRing::Standard),
            "sandboxed" => Ok(PrivilegeRing::Sandboxed),
            _ => Err(format!("Unknown privilege ring: {}", s)),
        }
    }
}

impl fmt::Display for PrivilegeRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivilegeRing::System => write!(f, "System"),
            PrivilegeRing::Trusted => write!(f, "Trusted"),
            PrivilegeRing::Standard => write!(f, "Standard"),
            PrivilegeRing::Sandboxed => write!(f, "Sandboxed"),
        }
    }
}

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
