use clap::{Parser, Subcommand};
use agent_mesh_core::identity::agent_id::AgentIdentity;
use agent_mesh_core::identity::risk::RiskScorer;
use agent_runtime_core::rings::enforcer::PrivilegeRing;
use agent_ext_mcp_governance::{PolicyEnforcer, McpTool};
use tracing_subscriber::EnvFilter;
use anyhow::Result;

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
            
            let identity = AgentIdentity::create(
                name.clone(),
                "admin@example.com".to_string(),
                vec!["compute".to_string(), "storage".to_string()],
                None,
                None,
            ).await?;
            
            println!("Agent Identity created: {}", identity.did);
            
            // Setup basic governance
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

            // Simulate tool calls
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
    }

    Ok(())
}

async fn test_tool_call(enforcer: &PolicyEnforcer, did: &str, ring: PrivilegeRing, tool: &str) {
    if enforcer.can_call_tool(did, ring, tool).await {
        println!("  [OK]  {} authorized for {}", did, tool);
    } else {
        println!("  [DENY] {} forbidden from using {}", did, tool);
    }
}
