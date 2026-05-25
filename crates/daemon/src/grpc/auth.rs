use agent_mesh_core::identity::AgentIdentity;
use agent_mesh_core::identity::registry::AgentRegistry;
use base64::{Engine as _, engine::general_purpose};
use tonic::{Request, Status};
use prost::Message;

pub async fn verify_request_signature(
    did: &str,
    signature: &[u8],
    body: &[u8],
    registry: &dyn AgentRegistry,
    registry_pubkey: &str,
) -> Result<(), String> {
    // 1. Attestation lookup and verification
    let attestation_opt = registry.get_attestation(did).await
        .map_err(|e| e.to_string())?;

    let attestation = attestation_opt.ok_or_else(|| "Agent not registered".to_string())?;
    
    attestation.verify(registry_pubkey)
        .map_err(|e| format!("Registry attestation verification failed: {}", e))?;

    let pubkey_b64 = attestation.claim.public_key_b64;

    // 2. Signature verification
    let identity_stub = AgentIdentity {
        public_key: pubkey_b64,
        did: agent_mesh_core::identity::agent_id::AgentDID { method: "".to_string(), unique_id: "".to_string() },
        name: "".to_string(),
        sponsor_email: "".to_string(),
        capabilities: vec![],
        status: "".to_string(),
        parent_did: None,
        delegation_depth: 0,
        private_key: None,
    };

    if !identity_stub.verify_signature(body, signature) {
        return Err("Invalid signature".to_string());
    }

    Ok(())
}

pub fn extract_grpc_auth(metadata: &tonic::metadata::MetadataMap) -> Result<(String, Vec<u8>), Status> {
    let did = metadata.get("x-agt-agent-did")
        .ok_or_else(|| Status::unauthenticated("Missing X-AGT-Agent-DID"))?
        .to_str().map_err(|_| Status::unauthenticated("Invalid DID format"))?;
    
    let signature_b64 = metadata.get("x-agt-signature")
        .ok_or_else(|| Status::unauthenticated("Missing X-AGT-Signature"))?
        .to_str().map_err(|_| Status::unauthenticated("Invalid signature format"))?;

    let signature = general_purpose::STANDARD.decode(signature_b64)
        .map_err(|_| Status::invalid_argument("Invalid Base64 in signature"))?;

    Ok((did.to_string(), signature))
}
