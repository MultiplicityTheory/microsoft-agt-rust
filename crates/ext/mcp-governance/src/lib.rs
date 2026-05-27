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
pub struct ClassificationRule {
    pub param_name: String,
    pub pattern: String,
    pub override_category: DataCategory,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub required_ring: PrivilegeRing,
    pub default_category: DataCategory,
    #[serde(default)]
    pub classification_rules: Vec<ClassificationRule>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct McpPolicy {
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub denylist: Vec<String>,
    #[serde(default)]
    pub allow_unknown_tools: bool,
    #[serde(default = "default_rps")]
    pub max_requests_per_second: u32,
}

fn default_rps() -> u32 { 10 }

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

    pub fn classify(&self, tool_name: &str, args: &Value) -> DataCategory {
        let tool = match self.tools.get(tool_name) {
            Some(t) => t,
            None => return DataCategory::Unknown,
        };

        let mut category = tool.default_category.clone();
        for rule in &tool.classification_rules {
            if let Some(val) = args.get(&rule.param_name).and_then(|v| v.as_str()) {
                if val.contains(&rule.pattern) {
                    category = rule.override_category.clone();
                    break;
                }
            }
        }
        category
    }

    pub async fn evaluate(
        &self,
        agent_did: &str,
        agent_ring: PrivilegeRing,
        tool_name: &str,
        args: &Value,
    ) -> EnforcementDecision {
        let tool = match self.tools.get(tool_name) {
            Some(t) => t,
            None => {
                warn!(tool = tool_name, "Tool not found in registry");
                
                // Check if policy allows unknown tools
                if let Ok(Some(policy)) = self.store.load_policy(agent_did).await {
                    if policy.allow_unknown_tools {
                        info!(agent_did = agent_did, tool = tool_name, "Allowing unknown tool per policy");
                        return EnforcementDecision::Allow;
                    }
                }
                
                return EnforcementDecision::Deny { reason: "Tool not registered in AGT mesh (fail-closed)".to_string() };
            }
        };

        let category = self.classify(tool_name, args);
        if category != tool.default_category {
            info!(tool = tool_name, category = ?category, "Argument-aware classification applied");
        }

        // 1. Check ring-based access via Runtime Enforcer
        if !Enforcer::can_execute(agent_did, agent_ring, tool.required_ring, tool_name) {
            if agent_ring > tool.required_ring {
                return EnforcementDecision::EscalateRequired { requested_ring: tool.required_ring };
            }
            return EnforcementDecision::Deny { reason: format!("Insufficient privilege ring: agent is {:?}, tool requires {:?}", agent_ring, tool.required_ring) };
        }

        // 2. Check specific policy if exists
        match self.store.load_policy(agent_did).await {
            Ok(Some(policy)) => {
                if policy.denylist.contains(&tool_name.to_string()) {
                    warn!(agent_did = agent_did, tool = tool_name, "Tool is in denylist for agent");
                    return EnforcementDecision::Deny { reason: "Tool explicitly denied by policy".to_string() };
                }
                if !policy.allowed_tools.is_empty() && !policy.allowed_tools.contains(&tool_name.to_string()) {
                    warn!(agent_did = agent_did, tool = tool_name, "Tool not in allowlist for agent");
                    return EnforcementDecision::Deny { reason: "Tool not in agent allowlist".to_string() };
                }
            },
            Ok(None) => {
                warn!(agent_did = agent_did, "No policy registered for agent");
                return EnforcementDecision::Deny { reason: "No policy registered for agent".to_string() };
            },
            Err(e) => {
                return EnforcementDecision::Deny { reason: format!("Policy store error: {}", e) };
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
        let agent_did = "agent-1";
        
        enforcer.register_tool(McpTool {
            name: "read_secret".to_string(),
            description: "Reads sensitive data".to_string(),
            required_ring: PrivilegeRing::Trusted,
            default_category: DataCategory::PersonalData,
            classification_rules: vec![],
        });

        // Register policy
        enforcer.set_policy(agent_did, McpPolicy {
            allowed_tools: vec!["read_secret".to_string()],
            denylist: vec![],
            allow_unknown_tools: false,
            max_requests_per_second: 10,
        }).await.unwrap();

        // Case 1: Insufficient ring -> EscalateRequired
        let decision = enforcer.evaluate(agent_did, PrivilegeRing::Standard, "read_secret", &Value::Null).await;
        assert_eq!(decision, EnforcementDecision::EscalateRequired { requested_ring: PrivilegeRing::Trusted });

        // Case 2: Sufficient ring -> Allow
        let decision2 = enforcer.evaluate(agent_did, PrivilegeRing::Trusted, "read_secret", &Value::Null).await;
        assert_eq!(decision2, EnforcementDecision::Allow);
    }

    #[tokio::test]
    async fn test_argument_aware_classification() {
        let mut enforcer = PolicyEnforcer::new(None);
        
        enforcer.register_tool(McpTool {
            name: "export".to_string(),
            description: "Export data".to_string(),
            required_ring: PrivilegeRing::Standard,
            default_category: DataCategory::SystemConfig,
            classification_rules: vec![
                ClassificationRule {
                    param_name: "target".to_string(),
                    pattern: "user_pii".to_string(),
                    override_category: DataCategory::PersonalData,
                }
            ],
        });

        // Case 1: Default category
        let category = enforcer.classify("export", &serde_json::json!({"target": "logs"}));
        assert_eq!(category, DataCategory::SystemConfig);

        // Case 2: Override category
        let category2 = enforcer.classify("export", &serde_json::json!({"target": "user_pii_table"}));
        assert_eq!(category2, DataCategory::PersonalData);
    }
}
