# Proposed Cargo Workspace Architecture

## Overview
A unified `microsoft-agt` Rust project will be structured as a Cargo workspace to ensure modularity, fast compilation, and clean separation of concerns.

## Workspace Structure (`Cargo.toml`)
```toml
[workspace]
members = [
    "crates/core/os",
    "crates/core/mesh",
    "crates/core/runtime",
    "crates/core/sre",
    "crates/ext/compliance",
    "crates/ext/discovery",
    "crates/ext/hypervisor",
    "crates/ext/lightning",
    "crates/ext/marketplace",
    "crates/ext/mcp-governance",
    "crates/integrations/adapter-core",
    "crates/integrations/langchain",
    "crates/integrations/autogen",
    "crates/cli",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["Microsoft-AGT Rust Migration Team"]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
anyhow = "1.0"
# Add other shared dependencies here
```

## Module Responsibilities
- `crates/core/*`: Core governance components (OS, Mesh, Runtime, SRE).
- `crates/ext/*`: Extension/specialized components (Compliance, Discovery, etc.).
- `crates/integrations/*`: Framework-specific adapters.
- `crates/cli`: Unified command-line interface.
