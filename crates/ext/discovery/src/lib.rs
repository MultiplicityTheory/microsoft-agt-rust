use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use agent_mesh_core::identity::agent_id::AgentDID;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoveredAgent {
    pub did: AgentDID,
    pub name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub transport_address: String,
    pub is_registered: bool,
}

pub struct DiscoveryManager {
    agents: Arc<RwLock<HashMap<String, DiscoveredAgent>>>,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn report_presence(&self, did: AgentDID, name: String, address: String) {
        let mut agents = self.agents.write().unwrap();
        let did_str = did.to_string();
        
        let entry = agents.entry(did_str.clone()).or_insert_with(|| {
            info!(did = %did, name = %name, "New agent discovered");
            DiscoveredAgent {
                did: did.clone(),
                name: name.clone(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                transport_address: address.clone(),
                is_registered: false, // Initially unregistered
            }
        });

        entry.last_seen = Utc::now();
        entry.transport_address = address;
    }

    pub fn register_agent(&self, did: &str) {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(did) {
            agent.is_registered = true;
            info!(did = %did, "Agent registered in discovery manager");
        }
    }

    pub fn detect_shadow_agents(&self) -> Vec<DiscoveredAgent> {
        let agents = self.agents.read().unwrap();
        let shadow_agents: Vec<DiscoveredAgent> = agents.values()
            .filter(|a| !a.is_registered)
            .cloned()
            .collect();

        if !shadow_agents.is_empty() {
            warn!(count = shadow_agents.len(), "Shadow agents detected in the mesh!");
            for agent in &shadow_agents {
                warn!(did = %agent.did, name = %agent.name, "Shadow Agent Alert");
            }
        }

        shadow_agents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_agent_detection() {
        let manager = DiscoveryManager::new();
        let did = AgentDID { method: "mesh".to_string(), unique_id: "test-shadow".to_string() };
        
        manager.report_presence(did.clone(), "ShadowBot".to_string(), "127.0.0.1:8080".to_string());
        
        let shadow_agents = manager.detect_shadow_agents();
        assert_eq!(shadow_agents.len(), 1);
        assert_eq!(shadow_agents[0].name, "ShadowBot");
        
        manager.register_agent(&did.to_string());
        let shadow_agents_after = manager.detect_shadow_agents();
        assert_eq!(shadow_agents_after.len(), 0);
    }
}
