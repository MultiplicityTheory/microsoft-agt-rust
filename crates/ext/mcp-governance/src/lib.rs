use agent_runtime_core::rings::enforcer::{Enforcer, PrivilegeRing};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{warn, info};
use anyhow::Result;

pub mod store;
use crate::store::{PolicyStore, MemoryPolicyStore};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub required_ring: PrivilegeRing,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpPolicy {
    pub allowed_tools: Vec<String>,
    pub denylist: Vec<String>,
}

pub struct PolicyEnforcer {
    tools: HashMap<String, McpTool>,
    store: Box<dyn PolicyStore>,
}

impl PolicyEnforcer {
    pub fn new(store: Option<Box<dyn PolicyStore>>) -> Self {
        Self {
            tools: HashMap::new(),
            store: store.unwrap_or_else(|| Box::new(MemoryPolicyStore::new())),
        }
    }

    pub fn register_tool(&mut self, tool: McpTool) {
        info!(tool = tool.name, "Registering MCP tool");
        self.tools.insert(tool.name.clone(), tool);
    }

    pub async fn set_policy(&mut self, agent_did: &str, policy: McpPolicy) -> Result<()> {
        info!(agent_did = agent_did, "Setting policy for agent");
        self.store.save_policy(agent_did, policy).await
    }

    pub async fn can_call_tool(
        &self,
        agent_did: &str,
        agent_ring: PrivilegeRing,
        tool_name: &str,
    ) -> bool {
        let tool = match self.tools.get(tool_name) {
            Some(t) => t,
            None => {
                warn!(tool = tool_name, "Tool not found");
                return false;
            }
        };

        // 1. Check ring-based access via Runtime Enforcer
        if !Enforcer::can_execute(agent_did, agent_ring, tool.required_ring, tool_name) {
            return false;
        }

        // 2. Check specific policy if exists
        if let Ok(Some(policy)) = self.store.load_policy(agent_did).await {
            if policy.denylist.contains(&tool_name.to_string()) {
                warn!(agent_did = agent_did, tool = tool_name, "Tool is in denylist for agent");
                return false;
            }
            if !policy.allowed_tools.is_empty() && !policy.allowed_tools.contains(&tool_name.to_string()) {
                warn!(agent_did = agent_did, tool = tool_name, "Tool not in allowlist for agent");
                return false;
            }
        }

        info!(agent_did = agent_did, tool = tool_name, "Tool call authorized");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_enforcement() {
        let mut enforcer = PolicyEnforcer::new(None);
        
        enforcer.register_tool(McpTool {
            name: "read_secret".to_string(),
            description: "Reads sensitive data".to_string(),
            required_ring: PrivilegeRing::Trusted,
        });

        // Case 1: Insufficient ring
        assert!(!enforcer.can_call_tool("agent-1", PrivilegeRing::Standard, "read_secret").await);

        // Case 2: Sufficient ring
        assert!(enforcer.can_call_tool("agent-1", PrivilegeRing::Trusted, "read_secret").await);

        // Case 3: Denylist
        enforcer.set_policy("agent-1", McpPolicy {
            allowed_tools: vec![],
            denylist: vec!["read_secret".to_string()],
        }).await.unwrap();
        assert!(!enforcer.can_call_tool("agent-1", PrivilegeRing::Trusted, "read_secret").await);
    }
}
