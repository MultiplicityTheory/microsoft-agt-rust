# ADR-003: HTTP+JSON Wire Protocol

## Status
Proposed / Accepted (Sprint 5 Phase 2)

## Context
As the AGT project moves toward a distributed model, a standardized network interface is required for agents to interact with the central registry, policy store, and escalation manager.

## Decisions

### 1. Protocol Choice: HTTP/1.1 + JSON
- **Choice:** HTTP/1.1 with JSON payloads via the `axum` framework.
- **Rationale:** High visibility for compliance auditors (curl/jq readable), mature ecosystem, and rapid iteration without proto IDL overhead.
- **Migration Path:** gRPC (via `tonic`) is the 90-day target once the API surface is stable.

### 2. Authentication: Request Signing
- **Header:** `X-AGT-Signature`: Ed25519 signature of the request body.
- **Header:** `X-AGT-Agent-DID`: The DID of the agent making the request.
- **Mechanism:** The server retrieves the public key for the provided DID from the `AgentRegistry` and verifies the signature before processing the request. 
- **Inbound Validation:** All wire types derive `Serialize`, `Deserialize`, and include `#[serde(deny_unknown_fields)]`.

### 3. API Surface (v1)

| Method | Path | Action |
|---|---|---|
| `POST` | `/v1/agents/register` | Registers an `AgentIdentity` + `PrivilegeRing`. |
| `GET` | `/v1/agents/:did/policy` | Loads the `McpPolicy` for an agent. |
| `POST` | `/v1/agents/:did/policy` | Saves the `McpPolicy` for an agent. |
| `GET` | `/v1/escalations/pending` | Lists all pending escalation requests. |
| `POST` | `/v1/escalations/:id/approve` | Approves an escalation (body contains signature). |
| `POST` | `/v1/presence` | Reports agent presence to `DiscoveryManager`. |
| `GET` | `/v1/discovery/shadows` | Lists detected shadow agents. |

## Rationale
- **Stateless Verification:** Request signing allows the server to remain stateless regarding sessions while ensuring every action is authenticated.
- **JSONL Compatibility:** The use of JSON payloads ensures that `AgentServer` logs can be directly piped into existing audit pipelines.

## Security Considerations
- **Replay Attacks:** The v1 protocol does not include a nonce or timestamp in the signed payload. Replay protection is a 90-day target.
- **Registry Authority:** There is one authoritative `AgentServer` daemon per deployment. Cross-node registry synchronization is deferred.
