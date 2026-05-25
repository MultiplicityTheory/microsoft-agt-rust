use crate::grpc::proto;
use agent_mesh_core::identity::{AgentIdentity, PrivilegeRing, AgentDID};
use agent_mesh_core::identity::attestation::{SignedAttestation, AttestationClaim};
use agent_ext_compliance::DataCategory;
use chrono::{DateTime, Utc, TimeZone};
use prost_types::Timestamp;
use std::convert::{TryFrom, From};
use tonic::Status;

// --- Enums ---

pub fn to_proto_ring(ring: PrivilegeRing) -> i32 {
    let p_ring = match ring {
        PrivilegeRing::System => proto::PrivilegeRing::System,
        PrivilegeRing::Trusted => proto::PrivilegeRing::Trusted,
        PrivilegeRing::Standard => proto::PrivilegeRing::Standard,
        PrivilegeRing::Sandboxed => proto::PrivilegeRing::Sandboxed,
    };
    p_ring as i32
}

pub fn from_proto_ring(ring: i32) -> Result<PrivilegeRing, Status> {
    match proto::PrivilegeRing::try_from(ring) {
        Ok(proto::PrivilegeRing::System) => Ok(PrivilegeRing::System),
        Ok(proto::PrivilegeRing::Trusted) => Ok(PrivilegeRing::Trusted),
        Ok(proto::PrivilegeRing::Standard) => Ok(PrivilegeRing::Standard),
        Ok(proto::PrivilegeRing::Sandboxed) => Ok(PrivilegeRing::Sandboxed),
        _ => Err(Status::invalid_argument("Unknown PrivilegeRing")),
    }
}

pub fn to_proto_category(cat: DataCategory) -> i32 {
    let p_cat = match cat {
        DataCategory::PersonalData => proto::DataCategory::PersonalData,
        DataCategory::FinancialRecord => proto::DataCategory::FinancialRecord,
        DataCategory::AuditLog => proto::DataCategory::AuditLog,
        DataCategory::SystemConfig => proto::DataCategory::SystemConfig,
        DataCategory::Unknown => proto::DataCategory::CategoryUnknown,
    };
    p_cat as i32
}

pub fn from_proto_category(cat: i32) -> DataCategory {
    match proto::DataCategory::try_from(cat) {
        Ok(proto::DataCategory::PersonalData) => DataCategory::PersonalData,
        Ok(proto::DataCategory::FinancialRecord) => DataCategory::FinancialRecord,
        Ok(proto::DataCategory::AuditLog) => DataCategory::AuditLog,
        Ok(proto::DataCategory::SystemConfig) => DataCategory::SystemConfig,
        _ => DataCategory::Unknown,
    }
}

// --- Time ---

pub fn to_proto_timestamp(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

pub fn from_proto_timestamp(ts: Timestamp) -> Result<DateTime<Utc>, Status> {
    Utc.timestamp_opt(ts.seconds, ts.nanos as u32)
        .single()
        .ok_or_else(|| Status::invalid_argument("Invalid timestamp"))
}

// --- Structs ---

pub fn to_proto_did(did: AgentDID) -> proto::AgentDid {
    proto::AgentDid {
        method: did.method,
        unique_id: did.unique_id,
    }
}

pub fn from_proto_did(did: proto::AgentDid) -> AgentDID {
    AgentDID {
        method: did.method,
        unique_id: did.unique_id,
    }
}

pub fn to_proto_identity(id: AgentIdentity, ring: PrivilegeRing) -> proto::AgentIdentity {
    proto::AgentIdentity {
        did: Some(to_proto_did(id.did)),
        name: id.name,
        public_key_b64: id.public_key,
        sponsor_email: id.sponsor_email,
        capabilities: id.capabilities,
        ring: to_proto_ring(ring),
    }
}

pub fn from_proto_identity(id: proto::AgentIdentity) -> Result<AgentIdentity, Status> {
    Ok(AgentIdentity {
        did: from_proto_did(id.did.ok_or_else(|| Status::invalid_argument("Missing DID"))?),
        name: id.name,
        public_key: id.public_key_b64,
        sponsor_email: id.sponsor_email,
        capabilities: id.capabilities,
        status: "active".to_string(),
        parent_did: None,
        delegation_depth: 0,
        private_key: None,
    })
}

pub fn to_proto_attestation(sa: SignedAttestation) -> proto::SignedAttestation {
    proto::SignedAttestation {
        claim: Some(proto::AttestationClaim {
            subject_did: sa.claim.subject_did,
            public_key_b64: sa.claim.public_key_b64,
            issued_at: Some(to_proto_timestamp(sa.claim.issued_at)),
            expires_at: Some(to_proto_timestamp(sa.claim.expires_at)),
        }),
        registry_did: sa.registry_did,
        signature_b64: sa.signature_b64,
    }
}

pub fn from_proto_attestation(sa: proto::SignedAttestation) -> Result<SignedAttestation, Status> {
    let proto_claim = sa.claim.ok_or_else(|| Status::invalid_argument("Missing claim"))?;
    Ok(SignedAttestation {
        claim: AttestationClaim {
            subject_did: proto_claim.subject_did,
            public_key_b64: proto_claim.public_key_b64,
            issued_at: from_proto_timestamp(proto_claim.issued_at.ok_or_else(|| Status::invalid_argument("Missing issued_at"))?)?,
            expires_at: from_proto_timestamp(proto_claim.expires_at.ok_or_else(|| Status::invalid_argument("Missing expires_at"))?)?,
        },
        registry_did: sa.registry_did,
        signature_b64: sa.signature_b64,
    })
}
