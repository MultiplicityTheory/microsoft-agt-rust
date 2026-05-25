use tonic::{Request, Response, Status};
use crate::grpc::proto::{self, escalation_service_server::EscalationService};
use crate::grpc::auth::{extract_grpc_auth, verify_request_signature};
use crate::grpc::convert;
use agent_runtime_core::rings::escalation::EscalationManager;
use agent_mesh_core::identity::registry::AgentRegistry;
use std::sync::Arc;
use uuid::Uuid;
use prost::Message;
use base64::Engine as _;

pub struct EscalationServiceImpl {
    pub manager: Arc<EscalationManager>,
    pub registry: Arc<dyn AgentRegistry>,
    pub policy_store: Arc<dyn agent_ext_mcp_governance::store::PolicyStore>,
    pub registry_pubkey: String,
}

#[tonic::async_trait]
impl EscalationService for EscalationServiceImpl {
    async fn request_escalation(
        &self,
        request: Request<proto::EscalationRequest>,
    ) -> Result<Response<proto::EscalationResponse>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let domain_req = convert::from_proto_escalation_request(inner)?;
        let request_id = self.manager.request_escalation(domain_req);

        Ok(Response::new(proto::EscalationResponse {
            request_id: request_id.to_string(),
        }))
    }

    async fn approve(
        &self,
        request: Request<proto::ApproveRequest>,
    ) -> Result<Response<proto::EscalationEvent>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let request_id = Uuid::parse_str(&inner.request_id)
            .map_err(|_| Status::invalid_argument("Invalid request_id UUID"))?;
        
        let approval_sig = base64::engine::general_purpose::STANDARD.decode(&inner.signature_b64)
            .map_err(|_| Status::invalid_argument("Invalid Base64 in signature"))?;

        let event = self.manager.approve(request_id, &inner.approver_did, &approval_sig, self.registry.as_ref()).await
            .map_err(|e| Status::failed_precondition(e))?;

        Ok(Response::new(convert::to_proto_escalation_event(event)))
    }

    async fn deny(
        &self,
        request: Request<proto::DenyRequest>,
    ) -> Result<Response<proto::EscalationEvent>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let request_id = Uuid::parse_str(&inner.request_id)
            .map_err(|_| Status::invalid_argument("Invalid request_id UUID"))?;

        let event = self.manager.deny(request_id, &inner.approver_did, inner.cause).await
            .map_err(|e| Status::failed_precondition(e))?;

        Ok(Response::new(convert::to_proto_escalation_event(event)))
    }

    async fn list_pending(
        &self,
        request: Request<proto::ListPendingRequest>,
    ) -> Result<Response<proto::ListPendingResponse>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let pending = self.manager.pending_requests();
        let proto_pending = pending.into_iter()
            .map(|(_, req)| convert::to_proto_escalation_request(req))
            .collect();

        Ok(Response::new(proto::ListPendingResponse {
            pending: proto_pending,
        }))
    }

    async fn get_policy(
        &self,
        request: Request<proto::GetPolicyRequest>,
    ) -> Result<Response<proto::PolicyResponse>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let policy = self.policy_store.load_policy(&inner.agent_did).await
            .map_err(|e| Status::internal(e.to_string()))?;

        match policy {
            Some(p) => {
                let json = serde_json::to_string(&p).map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(proto::PolicyResponse {
                    success: true,
                    policy_json: json,
                    error: "".to_string(),
                }))
            }
            None => Ok(Response::new(proto::PolicyResponse {
                success: true,
                policy_json: "".to_string(),
                error: "Policy not found".to_string(),
            })),
        }
    }

    async fn set_policy(
        &self,
        request: Request<proto::SetPolicyRequest>,
    ) -> Result<Response<proto::PolicyResponse>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let policy: agent_ext_mcp_governance::McpPolicy = serde_json::from_str(&inner.policy_json)
            .map_err(|e| Status::invalid_argument(format!("Invalid policy JSON: {}", e)))?;

        self.policy_store.save_policy(&inner.agent_did, policy).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::PolicyResponse {
            success: true,
            policy_json: inner.policy_json,
            error: "".to_string(),
        }))
    }
}
