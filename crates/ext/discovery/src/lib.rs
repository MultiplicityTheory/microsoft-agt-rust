use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use agent_mesh_core::identity::agent_id::AgentDID;
use tokio::sync::broadcast;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DiscoverySource {
    Active,  // Self-reported via /v1/presence
    Passive, // Detected via unauthorized request traffic
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoveredAgent {
    pub did: AgentDID,
    pub name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub transport_address: String,
    pub is_registered: bool,
    pub source: DiscoverySource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryEvent {
    Presence(DiscoveredAgent),
    Shadow(DiscoveredAgent),
}

pub struct DiscoveryManager {
    agents: Arc<RwLock<HashMap<String, DiscoveredAgent>>>,
    event_tx: broadcast::Sender<DiscoveryEvent>,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            event_tx: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.event_tx.subscribe()
    }

    pub fn report_presence(&self, did: AgentDID, name: String, address: String, source: DiscoverySource) {
        let mut agents = self.agents.write().unwrap();
        let did_str = did.to_string();
        
        let mut is_new = false;
        let entry = agents.entry(did_str.clone()).or_insert_with(|| {
            is_new = true;
            info!(did = %did, name = %name, source = ?source, "New agent discovered");
            DiscoveredAgent {
                did: did.clone(),
                name: name.clone(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                transport_address: address.clone(),
                is_registered: false,
                source: source.clone(),
            }
        });

        entry.last_seen = Utc::now();
        entry.transport_address = address;
        
        // Upgrade from Passive to Active if the agent self-reports
        let mut was_passive = false;
        if source == DiscoverySource::Active && entry.source == DiscoverySource::Passive {
            entry.source = DiscoverySource::Active;
            entry.name = name;
            was_passive = true;
        }

        let event = if entry.is_registered {
            DiscoveryEvent::Presence(entry.clone())
        } else {
            DiscoveryEvent::Shadow(entry.clone())
        };

        // Send event if it's new discovery OR an upgrade from passive to active
        if is_new || was_passive {
            let _ = self.event_tx.send(event);
        }
    }

    pub fn register_agent(&self, did: &str) {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(did) {
            agent.is_registered = true;
            info!(did = %did, "Agent registered in discovery manager");
            let _ = self.event_tx.send(DiscoveryEvent::Presence(agent.clone()));
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
        
        manager.report_presence(did.clone(), "ShadowBot".to_string(), "127.0.0.1:8080".to_string(), DiscoverySource::Passive);
        
        let shadow_agents = manager.detect_shadow_agents();
        assert_eq!(shadow_agents.len(), 1);
        assert_eq!(shadow_agents[0].name, "ShadowBot");
        assert_eq!(shadow_agents[0].source, DiscoverySource::Passive);
        
        manager.register_agent(&did.to_string());
        let shadow_agents_after = manager.detect_shadow_agents();
        assert_eq!(shadow_agents_after.len(), 0);
    }

    #[tokio::test]
    async fn test_discovery_events() {
        let manager = DiscoveryManager::new();
        let mut rx = manager.subscribe();
        
        let did = AgentDID { method: "mesh".to_string(), unique_id: "event-test".to_string() };
        manager.report_presence(did.clone(), "TestBot".to_string(), "addr".to_string(), DiscoverySource::Active);
        
        let event = rx.recv().await.unwrap();
        match event {
            DiscoveryEvent::Shadow(a) => assert_eq!(a.name, "TestBot"),
            _ => panic!("Expected shadow event"),
        }
    }
}
