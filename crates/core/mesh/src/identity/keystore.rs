use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use anyhow::Result;

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn save_key(&self, agent_did: &str, key: SigningKey) -> Result<()>;
    async fn load_key(&self, agent_did: &str) -> Result<Option<SigningKey>>;
    async fn delete_key(&self, agent_did: &str) -> Result<()>;
}

pub struct MemoryKeyStore {
    keys: Arc<RwLock<HashMap<String, SigningKey>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn save_key(&self, agent_did: &str, key: SigningKey) -> Result<()> {
        let mut keys = self.keys.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        keys.insert(agent_did.to_string(), key);
        Ok(())
    }

    async fn load_key(&self, agent_did: &str) -> Result<Option<SigningKey>> {
        let keys = self.keys.read().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        Ok(keys.get(agent_did).cloned())
    }

    async fn delete_key(&self, agent_did: &str) -> Result<()> {
        let mut keys = self.keys.write().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        keys.remove(agent_did);
        Ok(())
    }
}
