pub mod auth;
pub mod convert;
pub mod registry;
pub mod discovery;
pub mod escalation;

pub mod proto {
    tonic::include_proto!("agt.v1");
}
