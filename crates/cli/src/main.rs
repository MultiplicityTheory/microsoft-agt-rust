use clap::{Parser, Subcommand};
use agent_mesh_core::identity::agent_id::AgentIdentity;
use agent_mesh_core::identity::risk::RiskScorer;
use agent_mesh_core::identity::keystore::{KeyStore, MemoryKeyStore, FileKeyStore};
use agent_mesh_core::identity::registry::{AgentRegistry, MemoryAgentRegistry};
use agent_mesh_core::identity::PrivilegeRing;
use agent_runtime_core::rings::escalation::{EscalationManager, EscalationRequest, approval_payload};
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
        #[arg(short, long)]
        did: String,
        #[arg(short, long)]
        to_ring: PrivilegeRing,
        #[arg(short, long)]
        reason: String,
    },
    /// Approve an escalation request
    Approve {
        #[arg(short, long)]
        id: Uuid,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
        #[arg(short, long)]
        registry_pubkey: String,
    },
    /// Deny an escalation request
    Deny {
        #[arg(short, long)]
        id: Uuid,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        cause: String,
    },
    /// List pending escalation requests
    List,
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
    /// Watch for new shadows (polling)
    Watch {
        #[arg(short, long, default_value = "http://localhost:7700")]
        server: String,
        #[arg(short, long)]
        approver_did: String,
        #[arg(short, long)]
        key_dir: PathBuf,
        #[arg(short, long, default_value = "5")]
        interval: u64,
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
            });
            enforcer.register_tool(McpTool {
                name: "read_logs".to_string(),
                description: "Reads application logs".to_string(),
                required_ring: PrivilegeRing::Standard,
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
                EscalateCommands::Request { did, to_ring, reason } => {
                    let manager = EscalationManager::new(None, "dummy-key".to_string())?;
                    let id = manager.request_escalation(EscalationRequest {
                        agent_did: did.clone(),
                        current_ring: PrivilegeRing::Standard,
                        requested_ring: to_ring,
                        reason: reason.clone(),
                        timestamp: Utc::now(),
                    });
                    println!("Escalation requested for {}. Request ID: {}", did, id);
                }
                EscalateCommands::Approve { id, approver_did, key_dir, registry_pubkey } => {
                    let passphrase = std::env::var("AGT_KEY_PASSPHRASE")
                        .unwrap_or_else(|_| "default-passphrase".to_string());
                    
                    let keystore = FileKeyStore::new(key_dir, &passphrase)?;
                    let signing_key = keystore.load_key(&approver_did).await?
                        .ok_or_else(|| anyhow::anyhow!("Private key not found for approver"))?;
                    
                    let registry = MemoryAgentRegistry::new(generate_signing_key(), "did:mesh:registry".to_string());
                    let pubkey_b64 = general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
                    let approver_identity = AgentIdentity {
                        did: agent_mesh_core::identity::agent_id::AgentDID { method: "mesh".to_string(), unique_id: "approver".to_string() },
                        name: "Approver".to_string(),
                        public_key: pubkey_b64,
                        sponsor_email: "".to_string(),
                        capabilities: vec![],
                        status: "active".to_string(),
                        parent_did: None,
                        delegation_depth: 0,
                        private_key: Some(signing_key.clone()),
                    };
                    registry.register(&approver_identity, PrivilegeRing::System).await?;

                    let manager = EscalationManager::new(None, registry_pubkey)?;
                    manager.request_escalation(EscalationRequest {
                        agent_did: "target-agent".to_string(),
                        current_ring: PrivilegeRing::Standard,
                        requested_ring: PrivilegeRing::Trusted,
                        reason: "CLI Demo".to_string(),
                        timestamp: Utc::now(),
                    });

                    let payload = approval_payload(&id, "target-agent", PrivilegeRing::Trusted);
                    let signature = approver_identity.sign(&payload).unwrap();

                    match manager.approve(id, &approver_did, &signature, &registry).await {
                        Ok(event) => println!("Escalation Approved: {:?}", event.outcome),
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                EscalateCommands::Deny { id, approver_did, cause } => {
                    let manager = EscalationManager::new(None, "dummy".to_string())?;
                    manager.request_escalation(EscalationRequest {
                        agent_did: "target-agent".to_string(),
                        current_ring: PrivilegeRing::Standard,
                        requested_ring: PrivilegeRing::Trusted,
                        reason: "CLI Demo".to_string(),
                        timestamp: Utc::now(),
                    });

                    match manager.deny(id, &approver_did, cause) {
                        Ok(event) => println!("Escalation Denied: {:?}", event.outcome),
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                EscalateCommands::List => {
                    let manager = EscalationManager::new(None, "dummy".to_string())?;
                    let pending = manager.pending_requests();
                    if pending.is_empty() {
                        println!("No pending escalation requests.");
                    } else {
                        for (id, req) in pending {
                            println!("{}: {} requests {:?} (Reason: {})", id, req.agent_did, req.requested_ring, req.reason);
                        }
                    }
                }
            }
        }
        Commands::Daemon { listen, grpc_listen, audit_log, action_log, init } => {
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

            let action_log_path = action_log.unwrap_or_else(|| PathBuf::from("action-log.jsonl"));
            let file_action_log = agent_ext_compliance::FileActionLog::open(action_log_path)?;

            let state = Arc::new(agent_daemon::ServerState {
                registry: Arc::new(MemoryAgentRegistry::new(generate_signing_key(), "did:mesh:registry".to_string())),
                key_store: Arc::new(agent_mesh_core::identity::keystore::MemoryKeyStore::new()),
                policy_store: Arc::new(agent_ext_mcp_governance::store::MemoryPolicyStore::new()),
                escalation_manager: Arc::new(EscalationManager::new(audit_log, registry_pubkey.clone())?),
                discovery_manager: Arc::new(DiscoveryManager::new()),
                compliance_verifier: Arc::new(agent_ext_compliance::ComplianceVerifier::default_policy()),
                action_log: Arc::new(file_action_log),
                registry_pubkey,
            });

            let server = agent_daemon::AgentServer::new(state);
            server.run(&listen, &grpc_listen).await?;
        }
        Commands::Discovery { subcommand } => {
            match subcommand {
                DiscoveryCommands::Scan { server, approver_did, key_dir } => {
                    let shadows = fetch_shadows(&server, &approver_did, &key_dir).await?;
                    print_shadows(&shadows);
                }
                DiscoveryCommands::Watch { server, approver_did, key_dir, interval } => {
                    println!("Watching for shadow agents on {} (interval: {}s)...", server, interval);
                    let mut interval_timer = tokio::time::interval(tokio::time::Duration::from_secs(interval));
                    loop {
                        interval_timer.tick().await;
                        match fetch_shadows(&server, &approver_did, &key_dir).await {
                            Ok(shadows) => {
                                if !shadows.is_empty() {
                                    println!("\n[ALERT] {} shadow agents detected!", shadows.len());
                                    print_shadows(&shadows);
                                }
                            }
                            Err(e) => eprintln!("Error fetching shadows: {}", e),
                        }
                    }
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
    }

    Ok(())
}

fn generate_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

async fn fetch_shadows(server: &str, did: &str, key_dir: &std::path::Path) -> Result<Vec<agent_ext_discovery::DiscoveredAgent>> {
    let passphrase = std::env::var("AGT_KEY_PASSPHRASE").unwrap_or_else(|_| "default-passphrase".to_string());
    let keystore = FileKeyStore::new(key_dir.to_path_buf(), &passphrase)?;
    let signing_key = keystore.load_key(did).await?.ok_or_else(|| anyhow::anyhow!("Key not found"))?;
    
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
