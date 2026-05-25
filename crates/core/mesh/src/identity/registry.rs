use async_trait::async_trait;
use crate::identity::agent_id::AgentIdentity;
use crate::identity::agent_id::PrivilegeRing;
use crate::identity::attestation::{AttestationClaim, SignedAttestation};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use anyhow::{Result, anyhow};
use chrono::{Utc, Duration};
use ed25519_dalek::{SigningKey, Signer};
use base64::{Engine as _, engine::general_purpose};

#[async_trait]
pub trait AgentRegistry: Send + Sync {
    async fn register(&self, identity: &AgentIdentity, ring: PrivilegeRing) -> Result<()>;
    async fn get_attestation(&self, did: &str) -> Result<Option<SignedAttestation>>;
    async fn get_ring(&self, did: &str) -> Result<Option<PrivilegeRing>>;
    async fn is_registered(&self, did: &str) -> Result<bool>;
}

pub struct MemoryAgentRegistry {
    entries: Arc<RwLock<HashMap<String, (String, PrivilegeRing)>>>, // did_str -> (public_key_b64, ring)
    registry_identity: SigningKey,
    registry_did: String,
}

impl MemoryAgentRegistry {
    pub fn new(registry_identity: SigningKey, registry_did: String) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            registry_identity,
            registry_did,
        }
    }
}

#[async_trait]
impl AgentRegistry for MemoryAgentRegistry {
    async fn register(&self, identity: &AgentIdentity, ring: PrivilegeRing) -> Result<()> {
        let mut entries = self.entries.write().map_err(|_| anyhow!("Lock poisoned"))?;
        entries.insert(identity.did.to_string(), (identity.public_key.clone(), ring));
        Ok(())
    }

    async fn get_attestation(&self, did: &str) -> Result<Option<SignedAttestation>> {
        let entries = self.entries.read().map_err(|_| anyhow!("Lock poisoned"))?;
        
        let (pubkey_b64, _) = match entries.get(did) {
            Some(e) => e,
            None => return Ok(None),
        };

        let claim = AttestationClaim {
            subject_did: did.to_string(),
            public_key_b64: pubkey_b64.clone(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
        };

        let payload = SignedAttestation::canonical_bytes(&claim);
        let signature = self.registry_identity.sign(&payload);
        let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

        Ok(Some(SignedAttestation {
            claim,
            registry_did: self.registry_did.clone(),
            signature_b64,
        }))
    }

    async fn get_ring(&self, did: &str) -> Result<Option<PrivilegeRing>> {
        let entries = self.entries.read().map_err(|_| anyhow!("Lock poisoned"))?;
        Ok(entries.get(did).map(|(_, ring)| *ring))
    }

    async fn is_registered(&self, did: &str) -> Result<bool> {
        let entries = self.entries.read().map_err(|_| anyhow!("Lock poisoned"))?;
        Ok(entries.contains_key(did))
    }
}
