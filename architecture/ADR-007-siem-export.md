# ADR-007: SIEM Export Architecture and Monitoring

## Status
Proposed / Accepted (Sprint 10)

## Context
Enterprise-grade compliance requires long-term retention and centralized monitoring of security events. Local audit logs (`action-log.jsonl`, `escalations.jsonl`) are susceptible to local compromise and lack the real-time alerting capabilities of a dedicated Security Information and Event Management (SIEM) system.

## Decisions

### 1. Unified Event Export
- **Events in Scope:** 
    - `ActionLogRecord` (from `agent-ext-compliance`)
    - `EscalationEvent` (from `agent-runtime-core`)
- **Format:** JSONL (JSON Lines), where each line is a self-contained event record. This matches our local storage format and is natively supported by most SIEMs (Splunk, Elastic, Sentinel).

### 2. Transport: HTTP/HTTPS
- **Mechanism:** The `SiemExporter` will perform an asynchronous `POST` request to a configured endpoint.
- **Protocol:** HTTP/1.1 or HTTP/2.
- **Reliability:** Implement an in-memory retry buffer with exponential backoff. Persistent segment-based buffering is a future 180-day target.

### 3. Exporter Trait
- **Location:** `agent-ext-compliance`
- **Definition:**
```rust
#[async_trait]
pub trait SiemExporter: Send + Sync {
    async fn export_action(&self, record: &ActionLogRecord) -> Result<()>;
    async fn export_escalation(&self, event: &EscalationEvent) -> Result<()>;
}
```

### 4. Implementation: `HttpSiemExporter`
- **Configuration:** `SIEM_ENDPOINT_URL`, `SIEM_AUTH_TOKEN`.
- **Security:** TLS is mandatory. Authentication via a shared `Bearer` token in the `Authorization` header.

## Rationale
- **Asynchronous Pushes:** Streaming events as they occur ensures that even if a node is destroyed immediately after a malicious action, the evidence has already been exported.
- **JSONL Consistency:** Using the same format for local logs and SIEM exports reduces the complexity of our serialization logic and facilitates easy local-to-remote log comparison.

## Deferred / Out of Scope
- **Syslog Support:** Native Syslog (UDP/TCP/TLS) export is deferred to a future iteration.
- **Persistent Outbound Queue:** Segment-based reliable delivery across restarts is out of scope for the 30-day window.
