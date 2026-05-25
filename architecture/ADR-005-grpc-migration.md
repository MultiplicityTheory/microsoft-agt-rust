# ADR-005: gRPC Migration and Protocol Hardening

## Status
Proposed / Accepted (Sprint 9)

## Context
The current HTTP+JSON wire protocol lacks enforced schema discipline and is limited to request-response patterns. To support high-throughput, distributed deployments and real-time alerts (shadow agents, presence), a move to a versioned, streaming-capable protocol is required.

## Decisions

### 1. Protocol Boundary: Dual Transport
- **gRPC (tonic):** Used for all **daemon-to-daemon** (service-to-service) communication. This includes registry synchronization, discovery streaming, and policy replication.
- **HTTP/1.1 (axum):** Maintained for **client-to-daemon** (CLI and Dashboard) communication. HTTP remains the primary tool for human operators due to its visibility and ease of use with standard tools like `curl` and `jq`.
- **Dual-Port Operation:** During the migration phase, the daemon will listen on both port 7700 (HTTP) and 7701 (gRPC).

### 2. Schema-First Design
- All core types and services are defined in `.proto` files located in the `proto/agt/v1/` directory.
- Shared types (e.g., `AgentIdentity`, `SignedAttestation`) are centralized in `types.proto` to ensure consistency.

### 3. Streaming Model: Resume-from-Timestamp
- **Requirement:** Critical alerts (Shadow detection) must not be lost during daemon restarts or network partitions.
- **Decision:** Streaming RPCs (e.g., `WatchShadows`) will include a `since_timestamp` field in the request. 
- **Mechanism:** 
    - The client is responsible for implementing a reconnection loop with exponential backoff.
    - Upon reconnection, the client passes the timestamp of the last successfully processed event.
    - The daemon fulfills the stream by replaying events from the persistent `ActionLog` starting at that timestamp before switching to real-time pushes.

### 4. Type Mapping Invariants
- `chrono::DateTime<Utc>` maps to `google.protobuf.Timestamp`.
- `uuid::Uuid` maps to `string`.
- Rust Enums (e.g., `PrivilegeRing`) map to Proto Enums with explicit `UNKNOWN` values at index 0.

## Rationale
- **Performance:** gRPC (HTTP/2) offers significantly lower latency and overhead for the high-frequency presence reports expected in large meshes.
- **Reliability:** Streaming allows for immediate push alerts for shadow agents, rather than relying on inefficient client polling.
- **Durability:** The "Resume-from-Timestamp" model leverages the work done in Sprint 8 (tamper-evident log) to provide event durability without complex in-memory buffering.

## Deprecation Timeline
- **v1.0 (Sprint 9):** Dual-port support enabled. HTTP/1.1 daemon-to-daemon endpoints marked as `Deprecated`.
- **v1.5 (90 days):** CLI endpoints migrated to gRPC (where beneficial) or hardened HTTP/3. HTTP/1.1 daemon-to-daemon endpoints removed.

## Security Considerations
- Request signing (X-AGT-Signature) remains the primary authentication mechanism for gRPC calls, implemented via gRPC metadata (Interceptors).
