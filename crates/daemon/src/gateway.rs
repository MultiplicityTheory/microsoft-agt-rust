use axum::{
    routing::post,
    Router, Json, extract::State,
    http::StatusCode,
    body::Bytes,
};
use std::sync::{Arc};
use tokio::sync::Mutex;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use anyhow::Result;
use crate::ServerState;
use agent_mesh_core::audit::{ActionLogRecord, ActionOutcome, DataCategory};
use agent_mesh_core::identity::EscalationRequest;
use agent_ext_mcp_governance::{EnforcementDecision, PolicyEnforcer};
use agent_ext_compliance::ComplianceInput;
use uuid::Uuid;
use chrono::{Utc, DateTime, Duration};
use tracing::{info, warn};
use base64::{Engine as _, engine::general_purpose};

#[derive(Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Serialize, Deserialize)]
struct EscalationAcceptedResponse {
    escalation_id: String,
    message: String,
}

pub async fn run_gateway(state: Arc<ServerState>, addr: &str, upstream_url: String) -> Result<()> {
    let gateway_state = Arc::new(GatewayState {
        server_state: state,
        upstream_url,
        last_requests: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/*path", post(mcp_proxy_handler))
        .with_state(gateway_state.clone());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("AGT Gateway listening on {} (upstream: {})", addr, gateway_state.upstream_url);
    axum::serve(listener, app).await.map_err(|e| anyhow::anyhow!(e))
}

struct GatewayState {
    server_state: Arc<ServerState>,
    upstream_url: String,
    last_requests: Mutex<HashMap<String, DateTime<Utc>>>,
}

async fn mcp_proxy_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, String)> {
    let did_str = headers.get("X-AGT-Agent-DID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Agent-DID".to_string()))?;

    let signature_b64 = headers.get("X-AGT-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Signature".to_string()))?;

    let signature = general_purpose::STANDARD.decode(signature_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Base64 in signature".to_string()))?;

    // 1. Verify Signature
    crate::grpc::auth::verify_request_signature(
        did_str,
        &signature,
        &body,
        state.server_state.registry.as_ref(),
        &state.server_state.registry_pubkey,
    ).await.map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let payload: JsonRpcRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))?;

    // 2. Governance check
    if payload.method == "tools/call" {
        let tool_name = payload.params.as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing tool name in tools/call".to_string()))?;

        let args = payload.params.as_ref()
            .and_then(|p| p.get("arguments"))
            .unwrap_or(&Value::Null);

        // Get agent info
        let ring = state.server_state.registry.get_ring(did_str).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Agent not registered".to_string()))?;

        // Rate Limiting
        let policy = state.server_state.policy_store.load_policy(did_str).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or_default();
        
        {
            let mut last_requests = state.last_requests.lock().await;
            let now = Utc::now();
            if let Some(last) = last_requests.get(did_str) {
                let interval = Duration::seconds(1) / policy.max_requests_per_second.max(1) as i32;
                if now - *last < interval {
                    warn!(agent_did = did_str, "Rate limit exceeded");
                    return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
                }
            }
            last_requests.insert(did_str.to_string(), now);
        }

        // A. Policy Enforcement
        let enforcer = PolicyEnforcer::new(Some(state.server_state.policy_store.clone()));
        let decision = enforcer.evaluate(did_str, ring, tool_name, args).await;

        match decision {
            EnforcementDecision::Deny { reason } => {
                log_denial(&state.server_state, did_str, tool_name, &reason, DataCategory::Unknown);
                return Err((StatusCode::FORBIDDEN, reason));
            }
            EnforcementDecision::EscalateRequired { requested_ring } => {
                let reason = format!("Tool {} requires {:?} ring. Escalation triggered.", tool_name, requested_ring);
                
                // Auto-trigger escalation request
                let req = EscalationRequest {
                    agent_did: did_str.to_string(),
                    current_ring: ring,
                    requested_ring,
                    reason: format!("Auto-escalation for tool: {}", tool_name),
                    timestamp: Utc::now(),
                };
                let escalation_id = state.server_state.escalation_manager.request_escalation(req);
                
                log_denial(&state.server_state, did_str, tool_name, &reason, DataCategory::Unknown);
                
                let res = EscalationAcceptedResponse {
                    escalation_id: escalation_id.to_string(),
                    message: reason,
                };
                return Err((StatusCode::ACCEPTED, serde_json::to_string(&res).unwrap_or_default()));
            }
            EnforcementDecision::Allow => {
                // B. Compliance Evaluation
                let category = enforcer.classify(tool_name, args);
                
                let history = state.server_state.action_log.load_history(did_str)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

                let input = ComplianceInput {
                    agent_did: did_str.to_string(),
                    agent_ring: ring,
                    agent_capabilities: vec![], // Placeholder
                    action: tool_name.to_string(),
                    resource_category: category.clone(),
                    action_history: history,
                    jurisdiction: None, // Placeholder
                };

                if !state.server_state.compliance_verifier.is_compliant(&input) {
                    let reason = "Compliance violation detected".to_string();
                    log_denial(&state.server_state, did_str, tool_name, &reason, category);
                    return Err((StatusCode::FORBIDDEN, reason));
                }
            }
        }

        // 3. Forward to upstream
        let client = reqwest::Client::new();
        let upstream_res = client.post(&state.upstream_url)
            .body(body) // Pass original body
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

        let res_json: Value = upstream_res.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

        // 4. Log success
        let category = enforcer.classify(tool_name, args);
        let record = ActionLogRecord {
            record_id: Uuid::new_v4(),
            agent_did: did_str.to_string(),
            action: tool_name.to_string(),
            resource_category: category, 
            timestamp: Utc::now(),
            outcome: ActionOutcome::Permitted,
            prev_hash: "".to_string(),
        };
        let _ = state.server_state.action_log.append(record);

        return Ok(Json(res_json));
    }

    // Generic forward for other methods (list_tools, etc.)
    let client = reqwest::Client::new();
    let upstream_res = client.post(&state.upstream_url)
        .body(body)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let res_json: Value = upstream_res.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(res_json))
}

fn log_denial(state: &ServerState, did: &str, tool: &str, reason: &str, category: DataCategory) {
    let record = ActionLogRecord {
        record_id: Uuid::new_v4(),
        agent_did: did.to_string(),
        action: tool.to_string(),
        resource_category: category,
        timestamp: Utc::now(),
        outcome: ActionOutcome::Denied { rule: "Governance".to_string(), reason: reason.to_string() },
        prev_hash: "".to_string(),
    };
    let _ = state.action_log.append(record);
}
