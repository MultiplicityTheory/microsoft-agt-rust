use axum::{
    routing::{get, post},
    Router, Json, extract::{Path, State, Request, ConnectInfo},
    http::{StatusCode, header::HeaderMap},
    middleware::{self, Next},
    response::Response,
};
use std::sync::Arc;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use agent_mesh_core::identity::{AgentIdentity, PrivilegeRing, AgentDID};
use agent_mesh_core::identity::registry::AgentRegistry;
use agent_mesh_core::identity::attestation::SignedAttestation;
use agent_mesh_core::identity::keystore::KeyStore;
use agent_mesh_core::identity::keystore_http::AttestedKeyResponse;
use agent_mesh_core::audit::{ActionLogRecord, ActionOutcome, DataCategory};
use agent_runtime_core::rings::escalation::EscalationManager;
use agent_ext_discovery::{DiscoveryManager, DiscoverySource, DiscoveryEvent};
use agent_ext_mcp_governance::store::PolicyStore;
use agent_ext_mcp_governance::McpPolicy;
use agent_ext_compliance::{ComplianceVerifier, ComplianceInput, ComplianceResult, FileActionLog, SiemExporter};
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;

pub mod grpc;
pub mod gateway;
use crate::grpc::proto::registry_service_server::RegistryServiceServer;
use crate::grpc::registry::RegistryServiceImpl;
use crate::grpc::proto::discovery_service_server::DiscoveryServiceServer;
use crate::grpc::discovery::DiscoveryServiceImpl;
use crate::grpc::proto::escalation_service_server::EscalationServiceServer;
use crate::grpc::escalation::EscalationServiceImpl;
use crate::grpc::auth::verify_request_signature;

pub struct ServerState {
    pub registry: Arc<dyn AgentRegistry>,
    pub key_store: Arc<dyn KeyStore>,
    pub policy_store: Arc<dyn PolicyStore>,
    pub escalation_manager: Arc<EscalationManager>,
    pub discovery_manager: Arc<DiscoveryManager>,
    pub compliance_verifier: Arc<ComplianceVerifier>,
    pub action_log: Arc<FileActionLog>,
    pub siem_exporter: Option<Arc<dyn SiemExporter>>,
    pub registry_pubkey: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub identity: AgentIdentity,
    pub ring: PrivilegeRing,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub approver_did: String,
    pub signature: String, // Base64
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceReport {
    pub name: String,
    pub address: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub action: String,
    pub resource_category: DataCategory,
    pub jurisdiction: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub success: bool,
    pub results: Vec<ComplianceResult>,
}

pub struct AgentServer {
    state: Arc<ServerState>,
}

impl AgentServer {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    pub async fn run(self, http_addr: &str, grpc_addr: &str) -> Result<()> {
        let app = Router::new()
            .route("/v1/agents/register", post(register_agent))
            .route("/v1/agents/{did}/attestation", get(get_attestation))
            .route("/v1/agents/{did}/ring", get(get_ring))
            .route("/v1/agents/{did}/policy", get(get_policy).post(save_policy))
            .route("/v1/agents/{did}/key", get(get_key).post(save_key))
            .route("/v1/escalations/pending", get(list_pending))
            .route("/v1/escalations/{id}/approve", post(approve_escalation))
            .route("/v1/presence", post(report_presence))
            .route("/v1/discovery/shadows", get(list_shadows))
            .route("/v1/execute", post(execute_action))
            .layer(middleware::from_fn_with_state(self.state.clone(), auth_middleware))
            .with_state(self.state.clone());

        let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
        tracing::info!("AgentServer HTTP listening on {}", http_addr);

        let registry_grpc = RegistryServiceImpl {
            registry: self.state.registry.clone(),
            registry_pubkey: self.state.registry_pubkey.clone(),
        };

        let discovery_grpc = DiscoveryServiceImpl {
            discovery_manager: self.state.discovery_manager.clone(),
            action_log: self.state.action_log.clone(),
            registry: self.state.registry.clone(),
            registry_pubkey: self.state.registry_pubkey.clone(),
        };

        let escalation_grpc = EscalationServiceImpl {
            manager: self.state.escalation_manager.clone(),
            registry: self.state.registry.clone(),
            policy_store: self.state.policy_store.clone(),
            registry_pubkey: self.state.registry_pubkey.clone(),
        };
        
        let grpc_addr_socket: SocketAddr = grpc_addr.parse()?;
        let grpc_server = tonic::transport::Server::builder()
            .add_service(RegistryServiceServer::new(registry_grpc))
            .add_service(DiscoveryServiceServer::new(discovery_grpc))
            .add_service(EscalationServiceServer::new(escalation_grpc))
            .serve(grpc_addr_socket);
        
        tracing::info!("AgentServer gRPC listening on {}", grpc_addr);

        // Start background worker to bridge DiscoveryEvents to ActionLog
        let discovery_manager = self.state.discovery_manager.clone();
        let action_log = self.state.action_log.clone();
        tokio::spawn(async move {
            let mut rx = discovery_manager.subscribe();
            while let Ok(event) = rx.recv().await {
                if matches!(event, DiscoveryEvent::Shadow(_)) {
                    let did = match &event { DiscoveryEvent::Shadow(a) => a.did.to_string(), _ => unreachable!() };
                    let _ = action_log.append(ActionLogRecord {
                        record_id: Uuid::new_v4(),
                        agent_did: did,
                        action: "discovery_alert".to_string(),
                        resource_category: DataCategory::Unknown,
                        timestamp: Utc::now(),
                        outcome: ActionOutcome::DiscoveryEvent { 
                            event_json: serde_json::to_string(&event).unwrap_or_default() 
                        },
                        prev_hash: "".to_string(),
                    });
                }
            }
        });

        tokio::select! {
            r = axum::serve(http_listener, app.into_make_service_with_connect_info::<SocketAddr>()) => r.map_err(|e| anyhow::anyhow!(e)),
            r = grpc_server => r.map_err(|e| anyhow::anyhow!(e)),
        }
    }
}

async fn auth_middleware(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let did_str = headers.get("X-AGT-Agent-DID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Agent-DID".to_string()))?;
    
    let signature_b64 = headers.get("X-AGT-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Signature".to_string()))?;

    let signature = general_purpose::STANDARD.decode(signature_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Base64 in signature".to_string()))?;

    let peer_addr = req.extensions().get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // 2. Body extraction
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    // 3. Signature verification (unified logic)
    if let Err(e) = verify_request_signature(did_str, &signature, &bytes, state.registry.as_ref(), &state.registry_pubkey).await {
        if e == "Agent not registered" {
             if let Ok(did) = parse_did(did_str) {
                state.discovery_manager.report_presence(did, "unknown".to_string(), peer_addr, DiscoverySource::Passive);
            }
        }
        return Err((StatusCode::UNAUTHORIZED, e));
    }

    let req = Request::from_parts(parts, axum::body::Body::from(bytes));
    let mut response = next.run(req).await;
    
    // Add deprecation header to HTTP responses
    response.headers_mut().insert("Deprecation", "true".parse().unwrap());
    
    Ok(response)
}

fn parse_did(s: &str) -> Result<AgentDID, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 || parts[0] != "did" || parts[1] != "mesh" {
        return Err("Invalid DID format".to_string());
    }
    Ok(AgentDID {
        method: "mesh".to_string(),
        unique_id: parts[2].to_string(),
    })
}

// Handlers

async fn register_agent(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.registry.register(&req.identity, req.ring).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    state.discovery_manager.register_agent(&req.identity.did.to_string());
    Ok(StatusCode::CREATED)
}

async fn get_attestation(
    Path(did): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Option<SignedAttestation>>, (StatusCode, String)> {
    state.registry.get_attestation(&did).await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn get_ring(
    Path(did): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Option<PrivilegeRing>>, (StatusCode, String)> {
    state.registry.get_ring(&did).await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn get_policy(
    Path(did): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Option<McpPolicy>>, (StatusCode, String)> {
    state.policy_store.load_policy(&did).await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn save_policy(
    Path(did): Path<String>,
    State(state): State<Arc<ServerState>>,
    Json(policy): Json<McpPolicy>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.policy_store.save_policy(&did, policy).await
        .map(|_| StatusCode::OK)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn get_key(
    Path(did): Path<String>,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Option<AttestedKeyResponse>>, (StatusCode, String)> {
    let key = state.key_store.load_key(&did).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let attestation = state.registry.get_attestation(&did).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Agent not in registry".to_string()))?;

    match key {
        Some(k) => {
            let key_b64 = general_purpose::STANDARD.encode(k.to_bytes());
            Ok(Json(Some(AttestedKeyResponse { key_b64, attestation })))
        }
        None => Ok(Json(None))
    }
}

async fn save_key(
    Path(did): Path<String>,
    State(state): State<Arc<ServerState>>,
    Json(key_b64): Json<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bytes = general_purpose::STANDARD.decode(key_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Base64".to_string()))?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key length".to_string()))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    state.key_store.save_key(&did, signing_key).await
        .map(|_| StatusCode::OK)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn list_pending(
    State(state): State<Arc<ServerState>>,
) -> Json<Vec<(Uuid, agent_mesh_core::identity::EscalationRequest)>> {
    Json(state.escalation_manager.pending_requests())
}

async fn approve_escalation(
    Path(id): Path<Uuid>,
    State(state): State<Arc<ServerState>>,
    Json(req): Json<ApproveRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let signature = general_purpose::STANDARD.decode(req.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    state.escalation_manager.approve(id, &req.approver_did, &signature, state.registry.as_ref()).await
        .map(|_| StatusCode::OK)
        .map_err(|e| (StatusCode::FORBIDDEN, e))
}

async fn report_presence(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<PresenceReport>,
) -> Result<StatusCode, (StatusCode, String)> {
    let did_str = headers.get("X-AGT-Agent-DID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Agent-DID".to_string()))?;
    
    let did = parse_did(did_str).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    
    state.discovery_manager.report_presence(did, req.name, addr.to_string(), DiscoverySource::Active);
    Ok(StatusCode::OK)
}

async fn list_shadows(
    headers: HeaderMap,
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<agent_ext_discovery::DiscoveredAgent>>, (StatusCode, String)> {
    let did = headers.get("X-AGT-Agent-DID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Agent-DID".to_string()))?;
    
    let ring = state.registry.get_ring(did).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Not registered".to_string()))?;
    
    if ring != PrivilegeRing::System {
        return Err((StatusCode::FORBIDDEN, "Only System-ring agents can query shadows".to_string()));
    }

    Ok(Json(state.discovery_manager.detect_shadow_agents()))
}

async fn execute_action(
    headers: HeaderMap,
    State(state): State<Arc<ServerState>>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, String)> {
    let did_str = headers.get("X-AGT-Agent-DID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Agent-DID".to_string()))?;

    // 1. Gather context
    let ring = state.registry.get_ring(did_str).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Agent not registered".to_string()))?;
    
    let history = state.action_log.load_history(did_str)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Note: We don't have capabilities in Registry yet, adding a placeholder
    let capabilities = vec![]; 

    let input = ComplianceInput {
        agent_did: did_str.to_string(),
        agent_ring: ring,
        agent_capabilities: capabilities,
        action: req.action.clone(),
        resource_category: req.resource_category.clone(),
        action_history: history,
        jurisdiction: req.jurisdiction.clone(),
    };

    // 2. Evaluate compliance
    let results = state.compliance_verifier.evaluate(&input);
    let is_compliant = state.compliance_verifier.is_compliant(&input);

    let outcome = if is_compliant {
        ActionOutcome::Permitted
    } else {
        // Find the first violation for the log
        let violation = results.iter().find_map(|r| {
            if let ComplianceResult::Violation { rule, reason } = r {
                Some((rule.clone(), reason.clone()))
            } else {
                None
            }
        }).unwrap_or_else(|| ("Unknown".to_string(), "Access denied".to_string()));
        
        ActionOutcome::Denied { rule: violation.0, reason: violation.1 }
    };

    // 3. Record action (both permitted and denied)
    let record = ActionLogRecord {
        record_id: Uuid::new_v4(),
        agent_did: did_str.to_string(),
        action: req.action.clone(),
        resource_category: req.resource_category,
        timestamp: Utc::now(),
        outcome: outcome.clone(),
        prev_hash: "".to_string(), // Filled by append()
    };
    
    state.action_log.append(record.clone()).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 4. SIEM Export
    if let Some(ref exporter) = state.siem_exporter {
        let _ = exporter.export_action(&record).await;
    }

    if !is_compliant {
        return Ok(Json(ExecuteResponse {
            success: false,
            results,
        }));
    }

    Ok(Json(ExecuteResponse {
        success: true,
        results,
    }))
}
