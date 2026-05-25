use axum::{
    routing::post,
    Router, Json, extract::State,
    http::StatusCode,
};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use anyhow::Result;
use crate::ServerState;
use agent_mesh_core::audit::{ActionLogRecord, ActionOutcome, DataCategory};
use agent_ext_mcp_governance::EnforcementDecision;
use agent_ext_compliance::ComplianceInput;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;

#[derive(Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

pub async fn run_gateway(state: Arc<ServerState>, addr: &str, upstream_url: String) -> Result<()> {
    let gateway_state = Arc::new(GatewayState {
        server_state: state,
        upstream_url,
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
}

async fn mcp_proxy_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<JsonRpcRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let did_str = headers.get("X-AGT-Agent-DID")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing X-AGT-Agent-DID".to_string()))?;

    // 1. Governance check
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

        // A. Policy Enforcement
        let enforcer = agent_ext_mcp_governance::PolicyEnforcer::new(Some(state.server_state.policy_store.clone()));
        let decision = enforcer.evaluate(did_str, ring, tool_name, args).await;

        match decision {
            EnforcementDecision::Deny { reason } => {
                log_denial(&state.server_state, did_str, tool_name, &reason);
                return Err((StatusCode::FORBIDDEN, reason));
            }
            EnforcementDecision::EscalateRequired { requested_ring } => {
                let reason = format!("Tool {} requires {:?} ring. Escalation required.", tool_name, requested_ring);
                log_denial(&state.server_state, did_str, tool_name, &reason);
                return Err((StatusCode::FORBIDDEN, reason));
            }
            EnforcementDecision::Allow => {
                // B. Compliance Evaluation
                let tool = enforcer.get_tool(tool_name);
                let category = tool.map(|t| t.default_category.clone()).unwrap_or(DataCategory::Unknown);
                
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
                    log_denial(&state.server_state, did_str, tool_name, &reason);
                    return Err((StatusCode::FORBIDDEN, reason));
                }
            }
        }

        // 2. Forward to upstream
        let client = reqwest::Client::new();
        let upstream_res = client.post(&state.upstream_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

        let res_json: Value = upstream_res.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

        // 3. Log success
        let record = ActionLogRecord {
            record_id: Uuid::new_v4(),
            agent_did: did_str.to_string(),
            action: tool_name.to_string(),
            resource_category: DataCategory::Unknown, // Inferred above
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
        .json(&payload)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let res_json: Value = upstream_res.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(res_json))
}

fn log_denial(state: &ServerState, did: &str, tool: &str, reason: &str) {
    let record = ActionLogRecord {
        record_id: Uuid::new_v4(),
        agent_did: did.to_string(),
        action: tool.to_string(),
        resource_category: DataCategory::Unknown,
        timestamp: Utc::now(),
        outcome: ActionOutcome::Denied { rule: "Governance".to_string(), reason: reason.to_string() },
        prev_hash: "".to_string(),
    };
    let _ = state.action_log.append(record);
}
