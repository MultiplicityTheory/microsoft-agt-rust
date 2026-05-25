use crate::rings::enforcer::PrivilegeRing;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EscalationRequest {
    pub agent_did: String,
    pub current_ring: PrivilegeRing,
    pub requested_ring: PrivilegeRing,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EscalationStatus {
    Pending,
    Approved { by_did: String, approved_at: DateTime<Utc> },
    Denied { by_did: String, reason: String, denied_at: DateTime<Utc> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EscalationRecord {
    pub request: EscalationRequest,
    pub status: EscalationStatus,
}

pub struct EscalationManager;

impl EscalationManager {
    pub fn approve_request(
        request: EscalationRequest,
        approver_did: &str,
        approver_ring: PrivilegeRing,
    ) -> Result<EscalationRecord, String> {
        // Only System ring can approve escalation
        if approver_ring != PrivilegeRing::System {
            return Err("Only System-ring agents can approve escalation".to_string());
        }

        if request.requested_ring >= request.current_ring {
            return Err("Requested ring must be more privileged (lower value) than current ring".to_string());
        }

        Ok(EscalationRecord {
            request,
            status: EscalationStatus::Approved {
                by_did: approver_did.to_string(),
                approved_at: Utc::now(),
            },
        })
    }
}
