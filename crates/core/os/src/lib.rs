use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::RwLock;
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutionContext {
    pub agent_id: String,
    pub policies: Vec<String>,
    pub history: Vec<HashMap<String, serde_json::Value>>,
    pub state_ref: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub signal: Option<String>,
    pub updated_context: Option<ExecutionContext>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[async_trait]
pub trait StateBackend: Send + Sync {
    async fn get(&self, key: &str) -> anyhow::Result<Option<HashMap<String, serde_json::Value>>>;
    async fn set(&self, key: &str, value: HashMap<String, serde_json::Value>, ttl: Option<u64>) -> anyhow::Result<()>;
    async fn delete(&self, key: &str) -> anyhow::Result<()>;
}

pub struct MemoryBackend {
    store: RwLock<HashMap<String, (HashMap<String, serde_json::Value>, Option<Instant>)>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl StateBackend for MemoryBackend {
    async fn get(&self, key: &str) -> anyhow::Result<Option<HashMap<String, serde_json::Value>>> {
        let mut store = self.store.write().unwrap();
        if let Some((value, expires_at)) = store.get(key) {
            if let Some(expiry) = expires_at {
                if Instant::now() >= *expiry {
                    store.remove(key);
                    return Ok(None);
                }
            }
            return Ok(Some(value.clone()));
        }
        Ok(None)
    }

    async fn set(&self, key: &str, value: HashMap<String, serde_json::Value>, ttl: Option<u64>) -> anyhow::Result<()> {
        let mut store = self.store.write().unwrap();
        let expiry = ttl.map(|t| Instant::now() + Duration::from_secs(t));
        store.insert(key.to_string(), (value, expiry));
        Ok(())
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let mut store = self.store.write().unwrap();
        store.remove(key);
        Ok(())
    }
}

pub struct StatelessKernel {
    backend: Box<dyn StateBackend>,
    policies: HashMap<String, serde_json::Value>,
}

impl StatelessKernel {
    pub fn new(backend: Option<Box<dyn StateBackend>>, policies: Option<HashMap<String, serde_json::Value>>) -> Self {
        Self {
            backend: backend.unwrap_or_else(|| Box::new(MemoryBackend::new())),
            policies: policies.unwrap_or_default(),
        }
    }

    pub async fn execute(
        &self,
        action: String,
        params: HashMap<String, serde_json::Value>,
        context: ExecutionContext,
    ) -> anyhow::Result<ExecutionResult> {
        // 1. Load external state
        let mut external_state = HashMap::new();
        if let Some(ref state_ref) = context.state_ref {
            if let Some(state) = self.backend.get(state_ref).await? {
                external_state = state;
            }
        }

        // 2. Check policies
        if let Err(e) = self.check_policies(&action, &params, &context.policies) {
            return Ok(ExecutionResult {
                success: false,
                data: None,
                error: Some(e),
                signal: Some("SIGKILL".to_string()),
                updated_context: None,
                metadata: HashMap::new(),
            });
        }

        // 3. Execute action (stub)
        let result = self.execute_action(&action, &params, &external_state);
        
        // 4. Update external state if needed
        let mut new_state_ref = context.state_ref.clone();
        if let Some(state_update) = result.get("state_update") {
            if let Some(update_map) = state_update.as_object() {
                for (k, v) in update_map {
                    external_state.insert(k.clone(), v.clone());
                }
            }
            if new_state_ref.is_none() {
                new_state_ref = Some(format!("state:{}", context.agent_id));
            }
            self.backend.set(new_state_ref.as_ref().unwrap(), external_state, None).await?;
        }

        // 5. Return result
        Ok(ExecutionResult {
            success: true,
            data: Some(result.get("data").cloned().unwrap_or(serde_json::Value::Null)),
            error: None,
            signal: None,
            updated_context: Some(ExecutionContext {
                agent_id: context.agent_id.clone(),
                policies: context.policies.clone(),
                history: context.history, // Should append action here
                state_ref: new_state_ref,
                metadata: context.metadata.clone(),
            }),
            metadata: HashMap::new(),
        })
    }

    fn check_policies(
        &self,
        action: &str,
        _params: &HashMap<String, serde_json::Value>,
        policy_names: &[String],
    ) -> Result<(), String> {
        for policy_name in policy_names {
            if let Some(policy) = self.policies.get(policy_name) {
                // Check blocked actions
                if let Some(blocked) = policy.get("blocked_actions").and_then(|v| v.as_array()) {
                    if blocked.iter().any(|a| a == action) {
                        return Err(format!("Action '{}' blocked by policy '{}'", action, policy_name));
                    }
                }
            }
        }
        Ok(())
    }

    fn execute_action(
        &self,
        _action: &str,
        _params: &HashMap<String, serde_json::Value>,
        _state: &HashMap<String, serde_json::Value>,
    ) -> HashMap<String, serde_json::Value> {
        // Placeholder for real action execution
        let mut res = HashMap::new();
        res.insert("data".to_string(), serde_json::json!({"status": "executed"}));
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stateless_kernel_execution() {
        let mut policies = HashMap::new();
        policies.insert("read_only".to_string(), serde_json::json!({
            "blocked_actions": ["file_write"]
        }));

        let kernel = StatelessKernel::new(None, Some(policies));

        let context = ExecutionContext {
            agent_id: "test-agent".to_string(),
            policies: vec!["read_only".to_string()],
            history: vec![],
            state_ref: None,
            metadata: HashMap::new(),
        };

        // Test allowed action
        let result = kernel.execute("read_file".to_string(), HashMap::new(), context.clone()).await.unwrap();
        assert!(result.success);
        assert_eq!(result.data, Some(serde_json::json!({"status": "executed"})));

        // Test blocked action
        let result_blocked = kernel.execute("file_write".to_string(), HashMap::new(), context).await.unwrap();
        assert!(!result_blocked.success);
        assert_eq!(result_blocked.signal, Some("SIGKILL".to_string()));
    }
}
