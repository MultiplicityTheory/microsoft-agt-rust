use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::path::PathBuf;
use std::fs;
use anyhow::{Result, anyhow};
use sha2::Digest;
use crate::McpPolicy;

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn save_policy(&self, agent_did: &str, policy: McpPolicy) -> Result<()>;
    async fn load_policy(&self, agent_did: &str) -> Result<Option<McpPolicy>>;
    async fn delete_policy(&self, agent_did: &str) -> Result<()>;
    async fn list_policies(&self) -> Result<HashMap<String, McpPolicy>>;
}

pub struct MemoryPolicyStore {
    policies: Arc<RwLock<HashMap<String, McpPolicy>>>,
}

impl MemoryPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl PolicyStore for MemoryPolicyStore {
    async fn save_policy(&self, agent_did: &str, policy: McpPolicy) -> Result<()> {
        let mut policies = self.policies.write().map_err(|_| anyhow!("Lock poisoned"))?;
        policies.insert(agent_did.to_string(), policy);
        Ok(())
    }

    async fn load_policy(&self, agent_did: &str) -> Result<Option<McpPolicy>> {
        let policies = self.policies.read().map_err(|_| anyhow!("Lock poisoned"))?;
        Ok(policies.get(agent_did).cloned())
    }

    async fn delete_policy(&self, agent_did: &str) -> Result<()> {
        let mut policies = self.policies.write().map_err(|_| anyhow!("Lock poisoned"))?;
        policies.remove(agent_did);
        Ok(())
    }

    async fn list_policies(&self) -> Result<HashMap<String, McpPolicy>> {
        let policies = self.policies.read().map_err(|_| anyhow!("Lock poisoned"))?;
        Ok(policies.clone())
    }
}

pub struct FilePolicyStore {
    base_dir: PathBuf,
}

impl FilePolicyStore {
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)?;
        }
        Ok(Self { base_dir })
    }

    fn get_path(&self, agent_did: &str) -> PathBuf {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, agent_did.as_bytes());
        let hash = hex::encode(sha2::Digest::finalize(hasher));
        self.base_dir.join(format!("{}.json", hash))
    }
}

#[async_trait]
impl PolicyStore for FilePolicyStore {
    async fn save_policy(&self, agent_did: &str, policy: McpPolicy) -> Result<()> {
        let path = self.get_path(agent_did);
        let json = serde_json::to_string_pretty(&policy)?;
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    async fn load_policy(&self, agent_did: &str) -> Result<Option<McpPolicy>> {
        let path = self.get_path(agent_did);
        if !path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(path)?;
        let policy = serde_json::from_str(&json)?;
        Ok(Some(policy))
    }

    async fn delete_policy(&self, agent_did: &str) -> Result<()> {
        let path = self.get_path(agent_did);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    async fn list_policies(&self) -> Result<HashMap<String, McpPolicy>> {
        let mut policies = HashMap::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                let json = fs::read_to_string(&path)?;
                // Note: We don't easily know the DID from the hash-named file, 
                // but this satisfies the trait. In a real system we might store the DID inside the JSON.
                if let Ok(policy) = serde_json::from_str::<McpPolicy>(&json) {
                    // For listing, we can use the hash as the key or the filename.
                    // Improving this would require storing the DID in the McpPolicy struct.
                    policies.insert(path.file_stem().unwrap().to_string_lossy().to_string(), policy);
                }
            }
        }
        Ok(policies)
    }
}

use ed25519_dalek::{SigningKey, Signer};
use base64::{Engine as _, engine::general_purpose};

pub struct HttpPolicyStore {
    base_url: String,
    agent_did: String,
    signing_key: SigningKey,
    client: reqwest::Client,
}

impl HttpPolicyStore {
    pub fn new(base_url: String, agent_did: String, signing_key: SigningKey) -> Self {
        Self {
            base_url,
            agent_did,
            signing_key,
            client: reqwest::Client::new(),
        }
    }

    fn sign_body(&self, body: &[u8]) -> String {
        general_purpose::STANDARD.encode(self.signing_key.sign(body).to_bytes())
    }
}

#[async_trait]
impl PolicyStore for HttpPolicyStore {
    async fn save_policy(&self, agent_did: &str, policy: McpPolicy) -> Result<()> {
        let url = format!("{}/v1/agents/{}/policy", self.base_url, agent_did);
        let body = serde_json::to_vec(&policy)?;
        let signature = self.sign_body(&body);

        let response = self.client.post(url)
            .header("X-AGT-Signature", signature)
            .header("X-AGT-Agent-DID", &self.agent_did)
            .body(body)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("Failed to save policy: {}", response.status()))
        }
    }

    async fn load_policy(&self, agent_did: &str) -> Result<Option<McpPolicy>> {
        let url = format!("{}/v1/agents/{}/policy", self.base_url, agent_did);
        let signature = self.sign_body(b""); // Empty body for GET

        let response = self.client.get(url)
            .header("X-AGT-Signature", signature)
            .header("X-AGT-Agent-DID", &self.agent_did)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            Err(anyhow!("Failed to load policy: {}", response.status()))
        }
    }

    async fn delete_policy(&self, _agent_did: &str) -> Result<()> {
        Err(anyhow!("Delete not implemented in HttpPolicyStore v1"))
    }

    async fn list_policies(&self) -> Result<HashMap<String, McpPolicy>> {
        Err(anyhow!("List not implemented in HttpPolicyStore v1"))
    }
}

use tonic::metadata::MetadataValue;

pub mod proto {
    tonic::include_proto!("agt.v1");
}

pub struct NetworkPolicyStore {
    server_addr: String,
    agent_did: String,
    signing_key: SigningKey,
}

impl NetworkPolicyStore {
    pub fn new(server_addr: String, agent_did: String, signing_key: SigningKey) -> Self {
        Self {
            server_addr,
            agent_did,
            signing_key,
        }
    }

    async fn get_client(&self) -> Result<proto::escalation_service_client::EscalationServiceClient<tonic::transport::Channel>> {
        proto::escalation_service_client::EscalationServiceClient::connect(self.server_addr.clone()).await
            .map_err(|e| anyhow!("Failed to connect to gRPC server: {}", e))
    }

    fn sign(&self, body: &[u8]) -> String {
        general_purpose::STANDARD.encode(self.signing_key.sign(body).to_bytes())
    }
}

#[async_trait]
impl PolicyStore for NetworkPolicyStore {
    async fn save_policy(&self, agent_did: &str, policy: McpPolicy) -> Result<()> {
        let mut client = self.get_client().await?;
        let policy_json = serde_json::to_string(&policy)?;
        
        let req_payload = proto::SetPolicyRequest {
            agent_did: agent_did.to_string(),
            policy_json,
        };

        let body_bytes = prost::Message::encode_to_vec(&req_payload);
        let signature = self.sign(&body_bytes);

        let mut request = tonic::Request::new(req_payload);
        request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(&self.agent_did)?);
        request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(signature)?);

        let response = client.set_policy(request).await?;
        if response.into_inner().success {
            Ok(())
        } else {
            Err(anyhow!("Failed to save policy via gRPC"))
        }
    }

    async fn load_policy(&self, agent_did: &str) -> Result<Option<McpPolicy>> {
        let mut client = self.get_client().await?;
        
        let req_payload = proto::GetPolicyRequest {
            agent_did: agent_did.to_string(),
        };

        let body_bytes = prost::Message::encode_to_vec(&req_payload);
        let signature = self.sign(&body_bytes);

        let mut request = tonic::Request::new(req_payload);
        request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(&self.agent_did)?);
        request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(signature)?);

        let response = client.get_policy(request).await?;
        let inner = response.into_inner();
        
        if inner.success && !inner.policy_json.is_empty() {
            let policy = serde_json::from_str(&inner.policy_json)?;
            Ok(Some(policy))
        } else {
            Ok(None)
        }
    }

    async fn delete_policy(&self, _agent_did: &str) -> Result<()> {
        Err(anyhow!("Delete not implemented in NetworkPolicyStore"))
    }

    async fn list_policies(&self) -> Result<HashMap<String, McpPolicy>> {
        Err(anyhow!("List not implemented in NetworkPolicyStore"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_policystore_roundtrip() {
        let dir = tempdir().unwrap();
        let store = FilePolicyStore::new(dir.path().to_path_buf()).unwrap();
        let agent_did = "did:mesh:test-agent";
        
        let policy = McpPolicy {
            allowed_tools: vec!["tool1".to_string()],
            denylist: vec!["tool2".to_string()],
        };

        store.save_policy(agent_did, policy.clone()).await.unwrap();
        let loaded_policy = store.load_policy(agent_did).await.unwrap().unwrap();
        
        assert_eq!(policy.allowed_tools, loaded_policy.allowed_tools);
        assert_eq!(policy.denylist, loaded_policy.denylist);
    }
}
