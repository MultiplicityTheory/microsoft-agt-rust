use tonic::{Request, Response, Status};
use crate::grpc::proto::{self, discovery_service_server::DiscoveryService};
use crate::grpc::auth::{extract_grpc_auth, verify_request_signature};
use crate::grpc::convert;
use agent_ext_discovery::{DiscoveryManager, DiscoverySource, DiscoveryEvent};
use agent_ext_compliance::{FileActionLog, ActionOutcome};
use std::sync::Arc;
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use futures_core::Stream;
use std::pin::Pin;
use chrono::Utc;

pub struct DiscoveryServiceImpl {
    pub discovery_manager: Arc<DiscoveryManager>,
    pub action_log: Arc<FileActionLog>,
    pub registry: Arc<dyn agent_mesh_core::identity::registry::AgentRegistry>,
    pub registry_pubkey: String,
}

#[tonic::async_trait]
impl DiscoveryService for DiscoveryServiceImpl {
    async fn report_presence(
        &self,
        request: Request<proto::PresenceReport>,
    ) -> Result<Response<proto::PresenceAck>, Status> {
        let (did_str, sig) = extract_grpc_auth(request.metadata())?;
        
        let inner = request.into_inner();
        let body_bytes = prost::Message::encode_to_vec(&inner);

        verify_request_signature(&did_str, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let did = agent_mesh_core::identity::agent_id::AgentDID::from_str(&did_str)
            .map_err(|e| Status::invalid_argument(e))?;

        self.discovery_manager.report_presence(did, inner.name, inner.address, DiscoverySource::Active);

        Ok(Response::new(proto::PresenceAck { success: true }))
    }

    type WatchShadowsStream = Pin<Box<dyn Stream<Item = Result<proto::ShadowAlert, Status>> + Send>>;

    async fn watch_shadows(
        &self,
        request: Request<proto::WatchShadowsRequest>,
    ) -> Result<Response<Self::WatchShadowsStream>, Status> {
        let (did_str, sig) = extract_grpc_auth(request.metadata())?;
        
        // Ring check: Only System ring can watch shadows
        let ring = self.registry.get_ring(&did_str).await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::unauthenticated("Agent not registered"))?;
        
        if ring != agent_mesh_core::identity::PrivilegeRing::System {
            return Err(Status::permission_denied("Only System-ring agents can watch shadows"));
        }

        let inner = request.into_inner();
        let body_bytes = prost::Message::encode_to_vec(&inner);

        verify_request_signature(&did_str, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let since = if let Some(ts) = inner.since_timestamp {
            convert::from_proto_timestamp(ts)?
        } else {
            Utc::now()
        };

        // 1. Replay from ActionLog
        let mut initial_alerts = Vec::new();
        if let Ok(records) = self.action_log.replay_since(since) {
            for record in records {
                if let ActionOutcome::DiscoveryEvent { event_json } = record.outcome {
                    if let Ok(DiscoveryEvent::Shadow(a)) = serde_json::from_str::<DiscoveryEvent>(&event_json) {
                        initial_alerts.push(proto::ShadowAlert {
                            did: Some(convert::to_proto_did(a.did)),
                            name: a.name,
                            detected_at: Some(convert::to_proto_timestamp(a.last_seen)),
                            transport_address: a.transport_address,
                        });
                    }
                }
            }
        }

        // 2. Subscribe to live events
        let rx = self.discovery_manager.subscribe();
        let live_stream = BroadcastStream::new(rx).filter_map(|res| {
            match res {
                Ok(DiscoveryEvent::Shadow(a)) => Some(Ok(proto::ShadowAlert {
                    did: Some(convert::to_proto_did(a.did)),
                    name: a.name,
                    detected_at: Some(convert::to_proto_timestamp(a.last_seen)),
                    transport_address: a.transport_address,
                })),
                _ => None,
            }
        });

        let full_stream = tokio_stream::iter(initial_alerts.into_iter().map(Ok)).chain(live_stream);

        Ok(Response::new(Box::pin(full_stream)))
    }
}

use std::str::FromStr;
fn parse_did(s: &str) -> Result<agent_mesh_core::identity::agent_id::AgentDID, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 || parts[0] != "did" || parts[1] != "mesh" {
        return Err("Invalid DID format".to_string());
    }
    Ok(agent_mesh_core::identity::agent_id::AgentDID {
        method: "mesh".to_string(),
        unique_id: parts[2].to_string(),
    })
}

impl FromStr for agent_mesh_core::identity::agent_id::AgentDID {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_did(s)
    }
}
