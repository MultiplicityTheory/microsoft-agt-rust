use clap::{Parser, Subcommand};
use agent_mesh_core::identity::agent_id::AgentIdentity;
use agent_mesh_core::identity::risk::RiskScorer;
use agent_mesh_core::identity::keystore::{KeyStore, MemoryKeyStore, FileKeyStore};
use agent_mesh_core::identity::registry::MemoryAgentRegistry;
use agent_mesh_core::identity::PrivilegeRing;
use agent_runtime_core::rings::escalation::EscalationManager;
use agent_ext_mcp_governance::{PolicyEnforcer, McpTool};
use agent_ext_discovery::{DiscoveryManager, DiscoverySource};
use tracing_subscriber::EnvFilter;
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use tonic::metadata::MetadataValue;

pub mod proto {
    tonic::include_proto!("agt.v1");
}

#[derive(Parser)]
#[command(name = "agt")]
#[command(about = "Microsoft-AGT Rust CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the agent
    Run {
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value = "Standard")]
        ring: PrivilegeRing,
    },
    /// Show agent status
    Status {
        #[arg(short, long)]
        did: String,
    },
    /// Manage privilege escalations
    Escalate {
        #[command(subcommand)]
        subcommand: EscalateCommands,
    },
    /// Run the AGT central server (daemon mode)
    Daemon {
        #[arg(short, long, default_value = "0.0.0.0:7700")]
        listen: String,
        #[arg(short = 'g', long, default_value = "0.0.0.0:7701")]
        grpc_listen: String,
        #[arg(long)]
        audit_log: Option<PathBuf>,
        #[arg(long)]
        action_log: Option<PathBuf>,
        #[arg(long)]
        registry_log: Option<PathBuf>,
        #[arg(long)]
        siem_endpoint: Option<String>,
        #[arg(long)]
        siem_token: Option<String>,
        /// Initialize a new registry keypair
        #[arg(long)]
        init: bool,
    },
    /// Audit discovered agents
    Discovery {
        #[command(subcommand)]
        subcommand: DiscoveryCommands,
    },
    /// Audit and verify logs
    Log {
        #[command(subcommand)]
        subcommand: LogCommands,
    },
    /// Run the AGT Gateway (MCP Governance Proxy)
    Gateway {
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        listen: String,
        #[arg(short, long)]
        upstream: String,
        #[arg(long)]
        action_log: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LogCommands {
    /// Verify the integrity of the action log hash chain
    Verify {
        #[arg(short, long, default_value = "action-log.jsonl")]
        log_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum EscalateCommands {
    /// Request privilege escalation
    Request {
        #[arg(short, long, default_value = "http://localhost:7701")]
        server: String,
        #[arg(short, long)]
        did: String,
        #[arg(short, long)]
        to_ring: PrivilegeRing,
        #[arg(short, long)]
        reason: String,
        #[arg(short, long)]
        key_dir: PathBuf,
    },
    /// Approve an escalation request
    Approve {
        #[arg(short, long, default_value = "http://localhost:7701")]
        server: String,
        #[arg(short, long)]
        id: Uuid,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
    },
    /// Deny an escalation request
    Deny {
        #[arg(short, long, default_value = "http://localhost:7701")]
        server: String,
        #[arg(short, long)]
        id: Uuid,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
        #[arg(short, long)]
        cause: String,
    },
    /// List pending escalation requests
    List {
        #[arg(short, long, default_value = "http://localhost:7701")]
        server: String,
        #[arg(short, long)]
        did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum DiscoveryCommands {
    /// Scan for shadow agents
    Scan {
        #[arg(short, long, default_value = "http://localhost:7700")]
        server: String,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
    },
    /// Watch for new shadows (streaming)
    Watch {
        #[arg(short, long, default_value = "http://localhost:7701")]
        grpc_server: String,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { name, ring } => {
            println!("Starting agent: {} with ring: {:?}", name, ring);
            
            // 1. Setup Infrastructure
            let keystore = MemoryKeyStore::new();
            let discovery = DiscoveryManager::new();
            
            // 2. Create Identity (with persistence)
            let identity = AgentIdentity::create(
                name.clone(),
                "admin@example.com".to_string(),
                vec!["compute".to_string(), "storage".to_string()],
                None,
                Some(&keystore),
            ).await?;
            
            println!("Agent Identity created: {}", identity.did);

            // 3. Report Presence to Discovery
            discovery.report_presence(
                identity.did.clone(), 
                identity.name.clone(), 
                "local://direct".to_string(),
                DiscoverySource::Active,
            );

            // 4. Verify Round-trip through KeyStore
            let identity_json = serde_json::to_string(&identity)?;
            let loaded_identity = AgentIdentity::load(&identity_json, &keystore).await?;
            if loaded_identity.private_key.is_some() {
                println!("Success: Identity private key recovered from KeyStore round-trip.");
            } else {
                println!("Warning: Identity private key missing after round-trip!");
            }
            
            // 5. Setup basic governance
            let mut enforcer = PolicyEnforcer::new(None);
            enforcer.register_tool(McpTool {
                name: "delete_database".to_string(),
                description: "Deletes the production database".to_string(),
                required_ring: PrivilegeRing::System,
                default_category: agent_mesh_core::audit::DataCategory::FinancialRecord,
            });
            enforcer.register_tool(McpTool {
                name: "read_logs".to_string(),
                description: "Reads application logs".to_string(),
                required_ring: PrivilegeRing::Standard,
                default_category: agent_mesh_core::audit::DataCategory::AuditLog,
            });

            // 6. Discovery Audit: Shadow Agent Detection
            println!("\nRunning Discovery Audit:");
            let shadows = discovery.detect_shadow_agents();
            if shadows.iter().any(|a| a.did == identity.did) {
                println!("  [ALERT] Agent {} is currently a shadow agent (unregistered in discovery).", identity.did);
            }

            discovery.register_agent(&identity.did.to_string());
            println!("  [INFO] Registering agent {}...", identity.did);
            
            let shadows_after = discovery.detect_shadow_agents();
            if shadows_after.is_empty() {
                println!("  [OK] No shadow agents detected.");
            }

            // 7. Simulate tool calls
            println!("\nTesting tool calls:");
            test_tool_call(&enforcer, &identity.did.to_string(), ring, "read_logs").await;
            test_tool_call(&enforcer, &identity.did.to_string(), ring, "delete_database").await;
            
            println!("\nAgent {} is now running (simulated).", name);
        }
        Commands::Status { did } => {
            println!("Querying status for agent: {}", did);
            let scorer = RiskScorer::new();
            if let Some(score) = scorer.get_score(&did) {
                println!("Risk Score Report:");
                println!("  Total Score: {}", score.total_score);
                println!("  Identity Score: {}", score.identity_score);
                println!("  Behavior Score: {}", score.behavior_score);
                println!("  Status: active");
            } else {
                eprintln!("Error: Agent with DID '{}' not found in registry.", did);
                std::process::exit(1);
            }
        }
        Commands::Escalate { subcommand } => {
            match subcommand {
                EscalateCommands::Request { server, did, to_ring, reason, key_dir } => {
                    use proto::escalation_service_client::EscalationServiceClient;
                    let mut client = EscalationServiceClient::connect(server).await?;
                    
                    let signing_key = load_key(&did, &key_dir).await?;
                    let req = proto::EscalationRequest {
                        agent_did: did.clone(),
                        current_ring: proto::PrivilegeRing::Standard as i32, // Mock
                        requested_ring: to_proto_ring(to_ring),
                        reason: reason.clone(),
                        timestamp: Some(to_proto_timestamp(Utc::now())),
                    };

                    let body_bytes = prost::Message::encode_to_vec(&req);
                    let signature = general_purpose::STANDARD.encode(signing_key.sign(&body_bytes).to_bytes());

                    let mut request = tonic::Request::new(req);
                    request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(did)?);
                    request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(signature)?);

                    let response = client.request_escalation(request).await?;
                    println!("Escalation requested. Request ID: {}", response.into_inner().request_id);
                }
                EscalateCommands::Approve { server, id, approver_did, key_dir } => {
                    use proto::escalation_service_client::EscalationServiceClient;
                    let mut client = EscalationServiceClient::connect(server).await?;
                    
                    let signing_key = load_key(&approver_did, &key_dir).await?;
                    let req = proto::ApproveRequest {
                        request_id: id.to_string(),
                        approver_did: approver_did.clone(),
                        signature_b64: "".to_string(), // Filled after signing
                    };
                    
                    let payload = format!("{}:target-agent:{}", id, proto::PrivilegeRing::Trusted as i32).into_bytes();
                    let approval_sig = general_purpose::STANDARD.encode(signing_key.sign(&payload).to_bytes());
                    
                    let mut req_final = req;
                    req_final.signature_b64 = approval_sig;

                    let body_bytes = prost::Message::encode_to_vec(&req_final);
                    let outer_sig = general_purpose::STANDARD.encode(signing_key.sign(&body_bytes).to_bytes());

                    let mut request = tonic::Request::new(req_final);
                    request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(approver_did)?);
                    request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(outer_sig)?);

                    let response = client.approve(request).await?;
                    println!("Escalation Approved: {}", response.into_inner().outcome);
                }
                EscalateCommands::Deny { server, id, approver_did, key_dir, cause } => {
                    use proto::escalation_service_client::EscalationServiceClient;
                    let mut client = EscalationServiceClient::connect(server).await?;
                    
                    let signing_key = load_key(&approver_did, &key_dir).await?;
                    let req = proto::DenyRequest {
                        request_id: id.to_string(),
                        approver_did: approver_did.clone(),
                        cause,
                    };

                    let body_bytes = prost::Message::encode_to_vec(&req);
                    let signature = general_purpose::STANDARD.encode(signing_key.sign(&body_bytes).to_bytes());

                    let mut request = tonic::Request::new(req);
                    request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(approver_did)?);
                    request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(signature)?);

                    let response = client.deny(request).await?;
                    println!("Escalation Denied: {}", response.into_inner().outcome);
                }
                EscalateCommands::List { server, did, key_dir } => {
                    use proto::escalation_service_client::EscalationServiceClient;
                    let mut client = EscalationServiceClient::connect(server).await?;
                    
                    let signing_key = load_key(&did, &key_dir).await?;
                    let req = proto::ListPendingRequest {};

                    let body_bytes = prost::Message::encode_to_vec(&req);
                    let signature = general_purpose::STANDARD.encode(signing_key.sign(&body_bytes).to_bytes());

                    let mut request = tonic::Request::new(req);
                    request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(did)?);
                    request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(signature)?);

                    let response = client.list_pending(request).await?;
                    let pending = response.into_inner().pending;
                    if pending.is_empty() {
                        println!("No pending escalation requests.");
                    } else {
                        for req in pending {
                            println!("{}: requests {:?} (Reason: {})", req.agent_did, req.requested_ring, req.reason);
                        }
                    }
                }
            }
        }
        Commands::Daemon { listen, grpc_listen, audit_log, action_log, registry_log, siem_endpoint, siem_token, init } => {
            if init {
                let registry_key = generate_signing_key();
                let registry_pubkey = general_purpose::STANDARD.encode(registry_key.verifying_key().to_bytes());
                let registry_did = format!("did:mesh:registry-{}", hex::encode(Uuid::new_v4().as_bytes()[..4].to_vec()));
                
                println!("Generating registry keypair...");
                println!("Registry DID: {}", registry_did);
                println!("Registry public key: {}", registry_pubkey);
                println!("\nAdd to agt.toml:");
                println!("  [registry]");
                println!("  did = \"{}\"", registry_did);
                println!("  public_key = \"{}\"", registry_pubkey);
                return Ok(());
            }

            let registry_pubkey = std::env::var("AGT_REGISTRY_PUBKEY")
                .unwrap_or_else(|_| "placeholder-replace-me".to_string());
            let registry_did = std::env::var("AGT_REGISTRY_DID")
                .unwrap_or_else(|_| "did:mesh:registry".to_string());

            let action_log_path = action_log.unwrap_or_else(|| PathBuf::from("action-log.jsonl"));
            let file_action_log = agent_ext_compliance::FileActionLog::open(action_log_path)?;

            let siem_exporter: Option<Arc<dyn agent_ext_compliance::SiemExporter>> = if let (Some(url), Some(token)) = (siem_endpoint, siem_token) {
                Some(Arc::new(agent_ext_compliance::HttpSiemExporter::new(url, token)))
            } else {
                None
            };

            use agent_mesh_core::identity::registry::{AgentRegistry, FileAgentRegistry};
            let registry: Arc<dyn AgentRegistry> = if let Some(path) = registry_log {
                Arc::new(FileAgentRegistry::open(path, generate_signing_key(), registry_did)?)
            } else {
                Arc::new(MemoryAgentRegistry::new(generate_signing_key(), registry_did))
            };

            let state = Arc::new(agent_daemon::ServerState {
                registry,
                key_store: Arc::new(agent_mesh_core::identity::keystore::MemoryKeyStore::new()),
                policy_store: Arc::new(agent_ext_mcp_governance::store::MemoryPolicyStore::new()),
                escalation_manager: Arc::new(EscalationManager::new(audit_log, registry_pubkey.clone(), siem_exporter.clone())?),
                discovery_manager: Arc::new(DiscoveryManager::new()),
                compliance_verifier: Arc::new(agent_ext_compliance::ComplianceVerifier::default_policy()),
                action_log: Arc::new(file_action_log),
                siem_exporter,
                registry_pubkey,
            });

            let server = agent_daemon::AgentServer::new(state);
            server.run(&listen, &grpc_listen).await?;
        }
        Commands::Discovery { subcommand } => {
            match subcommand {
                DiscoveryCommands::Scan { server, approver_did, key_dir } => {
                    let shadows = fetch_shadows_http(&server, &approver_did, &key_dir).await?;
                    print_shadows(&shadows);
                }
                DiscoveryCommands::Watch { grpc_server, approver_did, key_dir } => {
                    grpc_discovery_watch(&grpc_server, &approver_did, &key_dir).await?;
                }
            }
        }
        Commands::Log { subcommand } => {
            match subcommand {
                LogCommands::Verify { log_file } => {
                    let log = agent_ext_compliance::FileActionLog::open(log_file)?;
                    let violations = log.verify_chain()?;
                    
                    if violations.is_empty() {
                        println!("  ✓ Chain intact");
                    } else {
                        println!("  ✗ Chain compromised: {} violations detected", violations.len());
                        for v in violations {
                            println!("    Violation at index {}: Record {} has unexpected prev_hash", v.index, v.record_id);
                        }
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Gateway { listen, upstream, action_log } => {
            let registry_pubkey = std::env::var("AGT_REGISTRY_PUBKEY")
                .unwrap_or_else(|_| "placeholder".to_string());
            
            let action_log_path = action_log.unwrap_or_else(|| PathBuf::from("gateway-action-log.jsonl"));
            let file_action_log = agent_ext_compliance::FileActionLog::open(action_log_path)?;

            let state = Arc::new(agent_daemon::ServerState {
                registry: Arc::new(MemoryAgentRegistry::new(generate_signing_key(), "did:mesh:registry".to_string())),
                key_store: Arc::new(agent_mesh_core::identity::keystore::MemoryKeyStore::new()),
                policy_store: Arc::new(agent_ext_mcp_governance::store::MemoryPolicyStore::new()),
                escalation_manager: Arc::new(EscalationManager::new(None, registry_pubkey.clone(), None)?),
                discovery_manager: Arc::new(DiscoveryManager::new()),
                compliance_verifier: Arc::new(agent_ext_compliance::ComplianceVerifier::default_policy()),
                action_log: Arc::new(file_action_log),
                siem_exporter: None,
                registry_pubkey,
            });

            println!("Starting AGT Gateway on {} -> {}", listen, upstream);
            agent_daemon::gateway::run_gateway(state, &listen, upstream).await?;
        }
    }

    Ok(())
}

fn generate_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

async fn load_key(did: &str, key_dir: &std::path::Path) -> Result<SigningKey> {
    let passphrase = std::env::var("AGT_KEY_PASSPHRASE").unwrap_or_else(|_| "default-passphrase".to_string());
    let keystore = FileKeyStore::new(key_dir.to_path_buf(), &passphrase)?;
    keystore.load_key(did).await?.ok_or_else(|| anyhow::anyhow!("Key not found"))
}

async fn fetch_shadows_http(server: &str, did: &str, key_dir: &std::path::Path) -> Result<Vec<agent_ext_discovery::DiscoveredAgent>> {
    let signing_key = load_key(did, key_dir).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/discovery/shadows", server);
    
    let signature = general_purpose::STANDARD.encode(signing_key.sign(b"").to_bytes());
    
    let response = client.get(url)
        .header("X-AGT-Signature", signature)
        .header("X-AGT-Agent-DID", did)
        .send()
        .await?;
    
    if response.status().is_success() {
        Ok(response.json().await?)
    } else {
        Err(anyhow::anyhow!("Server error: {}", response.status()))
    }
}

async fn grpc_discovery_watch(server: &str, did: &str, key_dir: &std::path::Path) -> Result<()> {
    use proto::discovery_service_client::DiscoveryServiceClient;
    use proto::WatchShadowsRequest;

    let signing_key = load_key(did, key_dir).await?;

    println!("Watching for shadow agents on {} (gRPC)...", server);

    let mut client = DiscoveryServiceClient::connect(server.to_string()).await?;
    
    let request_payload = WatchShadowsRequest { since_timestamp: None };
    let body_bytes = prost::Message::encode_to_vec(&request_payload);
    let signature = general_purpose::STANDARD.encode(signing_key.sign(&body_bytes).to_bytes());

    let mut request = tonic::Request::new(request_payload);
    request.metadata_mut().insert("x-agt-agent-did", MetadataValue::try_from(did)?);
    request.metadata_mut().insert("x-agt-signature", MetadataValue::try_from(signature)?);

    let mut stream = client.watch_shadows(request).await?.into_inner();

    while let Some(alert) = stream.message().await? {
        println!("\n[ALERT] Shadow Agent Detected!");
        println!("  DID: {:?}", alert.did);
        println!("  Name: {}", alert.name);
        println!("  Transport: {}", alert.transport_address);
    }

    Ok(())
}

fn to_proto_ring(ring: PrivilegeRing) -> i32 {
    let p_ring = match ring {
        PrivilegeRing::System => proto::PrivilegeRing::System,
        PrivilegeRing::Trusted => proto::PrivilegeRing::Trusted,
        PrivilegeRing::Standard => proto::PrivilegeRing::Standard,
        PrivilegeRing::Sandboxed => proto::PrivilegeRing::Sandboxed,
    };
    p_ring as i32
}

fn to_proto_timestamp(dt: chrono::DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

fn print_shadows(shadows: &[agent_ext_discovery::DiscoveredAgent]) {
    if shadows.is_empty() {
        println!("No shadow agents detected.");
    } else {
        println!("{:<40} {:<10} {:<20} {:<10}", "DID", "Source", "Last Seen", "Transport");
        for s in shadows {
            println!("{:<40} {:<10?} {:<20} {:<10}", s.did.to_string(), s.source, s.last_seen.to_rfc3339(), s.transport_address);
        }
    }
}

async fn test_tool_call(enforcer: &PolicyEnforcer, did: &str, ring: PrivilegeRing, tool: &str) {
    if enforcer.can_call_tool(did, ring, tool).await {
        println!("  [OK]  {} authorized for {}", did, tool);
    } else {
        println!("  [DENY] {} forbidden from using {}", did, tool);
    }
}
