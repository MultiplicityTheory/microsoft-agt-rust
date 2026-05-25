use agent_mesh_core::identity::{AgentIdentity, PrivilegeRing};
use agent_mesh_core::identity::registry::AgentRegistry;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::{info, warn};
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
pub struct EscalationEvent {
    pub event_id: Uuid,
    pub agent_did: String,
    pub approver_did: String,
    pub from_ring: PrivilegeRing,
    pub to_ring: PrivilegeRing,
    pub outcome: EscalationOutcome,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EscalationOutcome {
    Approved,
    Denied { cause: String },
}

pub fn approval_payload(event_id: &Uuid, agent_did: &str, requested_ring: PrivilegeRing) -> Vec<u8> {
    format!("{}:{}:{}", event_id, agent_did, requested_ring).into_bytes()
}

pub struct EscalationManager {
    pending: Arc<RwLock<HashMap<Uuid, EscalationRequest>>>,
    audit_log: Option<Arc<Mutex<BufWriter<File>>>>,
    registry_pubkey: String,
}

impl EscalationManager {
    pub fn new(audit_log_path: Option<PathBuf>, registry_pubkey: String) -> Result<Self> {
        let audit_log = if let Some(path) = audit_log_path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            Some(Arc::new(Mutex::new(BufWriter::new(file))))
        } else {
            None
        };

        Ok(Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            audit_log,
            registry_pubkey,
        })
    }

    pub fn request_escalation(&self, request: EscalationRequest) -> Uuid {
        let event_id = Uuid::new_v4();
        let mut pending = self.pending.write().unwrap();
        pending.insert(event_id, request);
        event_id
    }

    pub async fn approve(
        &self,
        event_id: Uuid,
        approver_did: &str,
        signature: &[u8],
        registry: &dyn AgentRegistry,
    ) -> Result<EscalationEvent, String> {
        let request = {
            let mut pending = self.pending.write().unwrap();
            pending.remove(&event_id).ok_or_else(|| "Escalation request not found".to_string())?
        };

        // 1. Ring check (from registry)
        let approver_ring = registry.get_ring(approver_did).await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Approver DID not in registry".to_string())?;

        if approver_ring != PrivilegeRing::System {
            let event = self.create_denied_event(event_id, &request, approver_did, "Only System-ring agents can approve escalation");
            warn!(event = ?event, "Escalation denied: insufficient approver privileges");
            let _ = self.log_event(&event);
            return Ok(event);
        }

        // 2. Attestation lookup and verification
        let attestation = registry.get_attestation(approver_did).await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Approver attestation not found".to_string())?;

        attestation.verify(&self.registry_pubkey)
            .map_err(|e| format!("Registry attestation verification failed: {}", e))?;

        let pubkey_b64 = attestation.claim.public_key_b64;

        // 3. Signature verification
        let payload = approval_payload(&event_id, &request.agent_did, request.requested_ring);
        let identity_stub = AgentIdentity {
            public_key: pubkey_b64,
            did: agent_mesh_core::identity::agent_id::AgentDID { method: "".to_string(), unique_id: "".to_string() },
            name: "".to_string(),
            sponsor_email: "".to_string(),
            capabilities: vec![],
            status: "".to_string(),
            parent_did: None,
            delegation_depth: 0,
            private_key: None,
        };

        if !identity_stub.verify_signature(&payload, signature) {
            let event = self.create_denied_event(event_id, &request, approver_did, "Approval signature invalid");
            warn!(event = ?event, "Escalation denied: invalid signature");
            let _ = self.log_event(&event);
            return Ok(event);
        }

        // 4. Ring transition check
        if request.requested_ring >= request.current_ring {
            let event = self.create_denied_event(event_id, &request, approver_did, "Requested ring must be more privileged");
            warn!(event = ?event, "Escalation denied: invalid ring transition");
            let _ = self.log_event(&event);
            return Ok(event);
        }

        let event = EscalationEvent {
            event_id,
            agent_did: request.agent_did.clone(),
            approver_did: approver_did.to_string(),
            from_ring: request.current_ring,
            to_ring: request.requested_ring,
            outcome: EscalationOutcome::Approved,
            reason: request.reason.clone(),
            timestamp: Utc::now(),
        };

        info!(event = ?event, "Escalation approved");
        let _ = self.log_event(&event);
        Ok(event)
    }

    fn create_denied_event(&self, event_id: Uuid, request: &EscalationRequest, approver_did: &str, cause: &str) -> EscalationEvent {
        EscalationEvent {
            event_id,
            agent_did: request.agent_did.clone(),
            approver_did: approver_did.to_string(),
            from_ring: request.current_ring,
            to_ring: request.requested_ring,
            outcome: EscalationOutcome::Denied { cause: cause.to_string() },
            reason: request.reason.clone(),
            timestamp: Utc::now(),
        }
    }

    pub fn deny(
        &self,
        event_id: Uuid,
        approver_did: &str,
        cause: String,
    ) -> Result<EscalationEvent, String> {
        let request = {
            let mut pending = self.pending.write().unwrap();
            pending.remove(&event_id).ok_or_else(|| "Escalation request not found".to_string())?
        };

        let event = EscalationEvent {
            event_id,
            agent_did: request.agent_did,
            approver_did: approver_did.to_string(),
            from_ring: request.current_ring,
            to_ring: request.requested_ring,
            outcome: EscalationOutcome::Denied { cause },
            reason: request.reason,
            timestamp: Utc::now(),
        };
        warn!(event = ?event, "Escalation explicitly denied");
        let _ = self.log_event(&event);
        Ok(event)
    }

    fn log_event(&self, event: &EscalationEvent) -> Result<()> {
        if let Some(ref audit_log) = self.audit_log {
            let mut writer = audit_log.lock().map_err(|_| anyhow::anyhow!("Audit log lock poisoned"))?;
            let json = serde_json::to_string(event)?;
            writer.write_all(json.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        Ok(())
    }

    pub fn pending_requests(&self) -> Vec<(Uuid, EscalationRequest)> {
        let pending = self.pending.read().unwrap();
        pending.iter().map(|(id, req)| (*id, req.clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::identity::registry::MemoryAgentRegistry;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use base64::{Engine as _, engine::general_purpose};

    fn generate_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[tokio::test]
    async fn test_escalation_signed_approval() {
        let registry_key = generate_signing_key();
        let registry_pubkey = general_purpose::STANDARD.encode(registry_key.verifying_key().to_bytes());
        
        let registry = MemoryAgentRegistry::new(registry_key, "did:mesh:registry".to_string());
        
        // 1. Setup Approver (System ring)
        let approver = AgentIdentity::create(
            "admin".to_string(),
            "admin@mesh".to_string(),
            vec![],
            None,
            None,
        ).await.unwrap();
        registry.register(&approver, PrivilegeRing::System).await.unwrap();

        let manager = EscalationManager::new(None, registry_pubkey).unwrap();
        
        let request = EscalationRequest {
            agent_did: "did:mesh:agent-1".to_string(),
            current_ring: PrivilegeRing::Standard,
            requested_ring: PrivilegeRing::Trusted,
            reason: "Signed test".to_string(),
            timestamp: Utc::now(),
        };

        let id = manager.request_escalation(request.clone());
        
        // 2. Sign approval
        let payload = approval_payload(&id, &request.agent_did, request.requested_ring);
        let signature = approver.sign(&payload).unwrap();

        // 3. Approve with valid signature
        let result = manager.approve(id, &approver.did.to_string(), &signature, &registry).await.unwrap();
        assert!(matches!(result.outcome, EscalationOutcome::Approved));
    }
}
