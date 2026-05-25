use tonic::{Request, Response, Status};
use crate::grpc::proto::{self, registry_service_server::RegistryService};
use crate::grpc::auth::{extract_grpc_auth, verify_request_signature};
use crate::grpc::convert;
use agent_mesh_core::identity::registry::AgentRegistry;
use std::sync::Arc;
use prost::Message;
use futures_core::Stream;
use std::pin::Pin;

pub struct RegistryServiceImpl {
    pub registry: Arc<dyn AgentRegistry>,
    pub registry_pubkey: String,
}

#[tonic::async_trait]
impl RegistryService for RegistryServiceImpl {
    async fn register(
        &self,
        request: Request<proto::RegisterRequest>,
    ) -> Result<Response<proto::RegisterResponse>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let identity = convert::from_proto_identity(inner.identity.ok_or_else(|| Status::invalid_argument("Missing identity"))?)?;
        let ring = convert::from_proto_ring(inner.ring)?;

        self.registry.register(&identity, ring).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::RegisterResponse { success: true }))
    }

    async fn get_attestation(
        &self,
        request: Request<proto::GetAttestationRequest>,
    ) -> Result<Response<proto::SignedAttestation>, Status> {
        let (did, sig) = extract_grpc_auth(request.metadata())?;
        
        let inner = request.into_inner();
        let body_bytes = inner.encode_to_vec();

        verify_request_signature(&did, &sig, &body_bytes, self.registry.as_ref(), &self.registry_pubkey).await
            .map_err(|e| Status::unauthenticated(e))?;

        let attestation = self.registry.get_attestation(&inner.did).await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("Attestation not found"))?;

        Ok(Response::new(convert::to_proto_attestation(attestation)))
    }

    type WatchPresenceStream = Pin<Box<dyn Stream<Item = Result<proto::PresenceEvent, Status>> + Send>>;

    async fn watch_presence(
        &self,
        _request: Request<proto::WatchPresenceRequest>,
    ) -> Result<Response<Self::WatchPresenceStream>, Status> {
        Err(Status::unimplemented("WatchPresence not implemented yet"))
    }
}
