# Microsoft Agent Governance Technology (AGT) - Rust Implementation

This repository contains the Rust implementation and migration of the Microsoft Agent Governance Technology (AGT) stack. Originally implemented in Python and TypeScript, this project transitions the core governance, identity, runtime, and security layers to Rust to achieve high performance, strict memory safety, and modularity.

## Repository Overview

The project is organized as a Cargo workspace containing the core framework, extensions, framework integrations, and a unified command-line tool.

### Workspace Structure

*   **`crates/core/`**: Core platform governance, runtime, and networking primitives.
    *   `agent-mesh-core` (`crates/core/mesh`): Zero-trust identity (DIDs), credentials, secure mTLS verification, transport layer (WebSockets), and namespace/access-control governance.
    *   `agent-os-core` (`crates/core/os`): The policy enforcement engine and stateless execution kernel.
    *   `agent-runtime-core` (`crates/core/runtime`): Agent lifecycle supervisor, privilege ring checks, and a Saga pattern orchestrator.
    *   `agent-sre-core` (`crates/core/sre`): Site reliability engineering primitives, including circuit breakers and chaos engineering.
*   **`crates/ext/`**: Specialized security and operational extension modules.
    *   `agent-ext-compliance` (`crates/ext/compliance`): Meta-level regulatory compliance engine (e.g., GDPR, HIPAA, SOX).
    *   `agent-ext-discovery` (`crates/ext/discovery`): Identification, inventorying, and risk-scoring of shadow/unregistered AI agents.
    *   `agent-ext-hypervisor` (`crates/ext/hypervisor`): Run-time action reversibility validation.
    *   `agent-ext-lightning` (`crates/ext/lightning`): Reinforced learning (RL) training governance.
    *   `agent-ext-marketplace` (`crates/ext/marketplace`): Agent plugin lifecycle verification and code signing.
    *   `agent-ext-mcp-governance` (`crates/ext/mcp-governance`): Model Context Protocol (MCP) security enforcements.
*   **`crates/integrations/`**: Adapters for popular agentic frameworks.
    *   `agent-int-adapter-core` (`crates/integrations/adapter-core`): Abstract interfaces for framework adapters.
    *   `agent-int-autogen` (`crates/integrations/autogen`): AutoGen framework integration.
    *   `agent-int-langchain` (`crates/integrations/langchain`): LangChain framework integration.
*   **`crates/cli/`** (`crates/cli`): The unified command-line interface for managing and running AGT governance components.

---

## HTTP API Deprecation Notice

The HTTP API on port 7700 is now **deprecated**. All clients should migrate to the gRPC API on port 7701. 
- HTTP responses now include the `Deprecation: true` header.
- The HTTP port will be disabled in a future release.

### Migration Guide

| Feature | HTTP Endpoint | gRPC Service |
|---|---|---|
| Registration | `POST /v1/agents/register` | `RegistryService.Register` |
| Attestation | `GET /v1/agents/:did/attestation` | `RegistryService.GetAttestation` |
| Discovery | `GET /v1/discovery/shadows` | `DiscoveryService.WatchShadows` (Stream) |
| Escalation | `POST /v1/escalations/:id/approve` | `EscalationService.Approve` |

#### Example: Watching Shadows (gRPC)
Use the AGT CLI to watch for shadow agents via gRPC:
```bash
agt discovery watch --grpc-server http://localhost:7701 --approver-did <your-did> --key-dir <path>
```

---

## Component Implementation Status

| Crate | Path | Status | Key Features / APIs Implemented |
|---|---|---|---|
| **agent-mesh-core** | `crates/core/mesh` | **Implemented** | `AgentIdentity`, `AgentDID`, `CredentialManager`, `KeyRotationManager`, `MTLSIdentityVerifier`, `NamespaceManager`, `WebSocketTransport` |
| **agent-os-core** | `crates/core/os` | **Implemented** | `StatelessKernel`, `StateBackend`, `MemoryBackend`, policy checking, action routing |
| **agent-runtime-core** | `crates/core/runtime` | **Partial** | `PrivilegeRing` checks (`Enforcer`), `SagaOrchestrator` shell |
| **agent-sre-core** | `crates/core/sre` | **Implemented** | `CircuitBreaker` (Closed/Open/HalfOpen states) |
| **agent-ext-compliance** | `crates/ext/compliance` | **Stub** | `ComplianceVerifier` skeleton |
| **Other Extensions** | `crates/ext/*` | **Stub** | Empty `lib.rs` (discovery, hypervisor, lightning, marketplace, mcp-governance) |
| **Integrations** | `crates/integrations/*` | **Stub** | Empty `lib.rs` (adapter-core, autogen, langchain) |
| **agent-cli** | `crates/cli` | **Stub** | Empty `lib.rs` |

---

## Developer Setup Guide

Follow these steps to set up, build, and verify the repository locally.

### 1. Prerequisites
Ensure you have the Rust toolchain installed. The project requires **Rust 1.70+** (2021 Edition).
If Rust is not installed, you can set it up via `rustup`:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Build the Workspace
To compile the entire workspace, run:
```bash
cargo build
```

To compile a specific crate:
```bash
cargo build -p agent-mesh-core
```

### 3. Run the Test Suite
Validate the implementation by running the unit tests:
```bash
cargo test
```

---

## Usage Examples

Here are some brief code snippets showcasing how the implemented modules are constructed and used.

### Zero-Trust Agent Identity & Key Rotation (`agent-mesh-core`)

```rust
use agent_mesh_core::identity::agent_id::AgentIdentity;
use agent_mesh_core::identity::rotation::KeyRotationManager;

// Create a new Agent Identity with specific capabilities
let mut identity = AgentIdentity::create(
    "auth-verifier".to_string(),
    "security-admin@company.com".to_string(),
    vec!["read_logs".to_string(), "revoke_tokens".to_string()],
    Some("security-mesh".to_string()),
);

println!("Agent DID: {}", identity.did);
println!("Agent Public Key: {}", identity.public_key);

// Perform a proactive key rotation
let old_key = identity.public_key.clone();
KeyRotationManager::rotate_keys(&mut identity);
assert_ne!(old_key, identity.public_key);
```

### Policy Enforcement & Stateless Evaluation (`agent-os-core`)

```rust
use agent_os_core::{StatelessKernel, ExecutionContext};
use std::collections::HashMap;

#[tokio::main]
async fn main() {
    let mut policies = HashMap::new();
    policies.insert("sandbox_policy".to_string(), serde_json::json!({
        "blocked_actions": ["execute_shell", "file_delete"]
    }));

    // Instantiate kernel with memory state backend and sandbox policy
    let kernel = StatelessKernel::new(None, Some(policies));

    let context = ExecutionContext {
        agent_id: "agent-123".to_string(),
        policies: vec!["sandbox_policy".to_string()],
        history: vec![],
        state_ref: None,
        metadata: HashMap::new(),
    };

    // Attempt to execute a blocked action
    let result = kernel.execute(
        "execute_shell".to_string(),
        HashMap::new(),
        context,
    ).await.unwrap();

    assert!(!result.success);
    println!("Execution status: {:?}", result.error); // Action blocked by policy
}
```

### Circuit Breaker (`agent-sre-core`)

```rust
use agent_sre_core::circuit_breaker::CircuitBreaker;
use std::time::Duration;

let breaker = CircuitBreaker::new(3, Duration::from_secs(5));

// Record 3 failures to trigger Open state
breaker.record_failure();
breaker.record_failure();
breaker.record_failure();

assert!(!breaker.is_allowed()); // Requests are now blocked
```
