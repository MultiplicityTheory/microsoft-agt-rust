use agent_runtime_core::rings::enforcer::Enforcer;
use agent_mesh_core::identity::PrivilegeRing;
use agent_mesh_core::audit::DataCategory;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    pub default_category: DataCategory,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpPolicy {
    pub allowed_tools: Vec<String>,
    pub denylist: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum EnforcementDecision {
    Allow,
    Deny { reason: String },
    EscalateRequired { requested_ring: PrivilegeRing },
}

pub struct PolicyEnforcer {
    tools: HashMap<String, McpTool>,
    store: Arc<dyn PolicyStore>,
}

impl PolicyEnforcer {
    pub fn new(store: Option<Arc<dyn PolicyStore>>) -> Self {
        Self {
            tools: HashMap::new(),
            store: store.unwrap_or_else(|| Arc::new(MemoryPolicyStore::new())),
        }
    }

    pub fn register_tool(&mut self, tool: McpTool) {
        info!(tool = tool.name, "Registering MCP tool");
        self.tools.insert(tool.name.clone(), tool);
    }

    pub fn get_tool(&self, name: &str) -> Option<&McpTool> {
        self.tools.get(name)
    }

    pub async fn set_policy(&self, agent_did: &str, policy: McpPolicy) -> Result<()> {
        info!(agent_did = agent_did, "Setting policy for agent");
        self.store.save_policy(agent_did, policy).await
    }

    pub async fn evaluate(
        &self,
        agent_did: &str,
        agent_ring: PrivilegeRing,
        tool_name: &str,
        _args: &Value,
    ) -> EnforcementDecision {
        let tool = match self.tools.get(tool_name) {
            Some(t) => t,
            None => {
                warn!(tool = tool_name, "Tool not found");
                return EnforcementDecision::Deny { reason: "Tool not found in AGT registry".to_string() };
            }
        };

        // 1. Check ring-based access via Runtime Enforcer
        if !Enforcer::can_execute(agent_did, agent_ring, tool.required_ring, tool_name) {
            if agent_ring > tool.required_ring {
                return EnforcementDecision::EscalateRequired { requested_ring: tool.required_ring };
            }
            return EnforcementDecision::Deny { reason: format!("Insufficient privilege ring: agent is {:?}, tool requires {:?}", agent_ring, tool.required_ring) };
        }

        // 2. Check specific policy if exists
        if let Ok(Some(policy)) = self.store.load_policy(agent_did).await {
            if policy.denylist.contains(&tool_name.to_string()) {
                warn!(agent_did = agent_did, tool = tool_name, "Tool is in denylist for agent");
                return EnforcementDecision::Deny { reason: "Tool explicitly denied by policy".to_string() };
            }
            if !policy.allowed_tools.is_empty() && !policy.allowed_tools.contains(&tool_name.to_string()) {
                warn!(agent_did = agent_did, tool = tool_name, "Tool not in allowlist for agent");
                return EnforcementDecision::Deny { reason: "Tool not in agent allowlist".to_string() };
            }
        }

        info!(agent_did = agent_did, tool = tool_name, "Tool call authorized");
        EnforcementDecision::Allow
    }

    pub async fn can_call_tool(
        &self,
        agent_did: &str,
        agent_ring: PrivilegeRing,
        tool_name: &str,
    ) -> bool {
        matches!(self.evaluate(agent_did, agent_ring, tool_name, &Value::Null).await, EnforcementDecision::Allow)
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_enforcement_v2() {
        let mut enforcer = PolicyEnforcer::new(None);
        
        enforcer.register_tool(McpTool {
            name: "read_secret".to_string(),
            description: "Reads sensitive data".to_string(),
            required_ring: PrivilegeRing::Trusted,
            default_category: DataCategory::PersonalData,
        });

        // Case 1: Insufficient ring -> EscalateRequired
        let decision = enforcer.evaluate("agent-1", PrivilegeRing::Standard, "read_secret", &Value::Null).await;
        assert_eq!(decision, EnforcementDecision::EscalateRequired { requested_ring: PrivilegeRing::Trusted });

        // Case 2: Sufficient ring -> Allow
        let decision2 = enforcer.evaluate("agent-1", PrivilegeRing::Trusted, "read_secret", &Value::Null).await;
        assert_eq!(decision2, EnforcementDecision::Allow);
    }
}
