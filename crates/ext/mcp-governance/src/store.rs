use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use anyhow::Result;
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
        let mut policies = self.policies.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        policies.insert(agent_did.to_string(), policy);
        Ok(())
    }

    async fn load_policy(&self, agent_did: &str) -> Result<Option<McpPolicy>> {
        let policies = self.policies.read().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        Ok(policies.get(agent_did).cloned())
    }

    async fn delete_policy(&self, agent_did: &str) -> Result<()> {
        let mut policies = self.policies.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        policies.remove(agent_did);
        Ok(())
    }

    async fn list_policies(&self) -> Result<HashMap<String, McpPolicy>> {
        let policies = self.policies.read().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        Ok(policies.clone())
    }
}
