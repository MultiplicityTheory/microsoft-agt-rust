# ADR-004: Attested Network Adapters and Trust Policy

## Status
Proposed / Accepted (Sprint 6)

## Context
With the introduction of Registry Attestations, every network-based identity lookup must be verified against the Registry's root public key. This ADR defines the behavior of network adapters (`HttpAgentRegistry`, `HttpKeyStore`) when interacting with these attestations.

## Decisions

### 1. Attested Registry Adapter
- **Requirement:** The `HttpAgentRegistry` (implementing the `AgentRegistry` trait) must verify every `SignedAttestation` returned by the server against the local `registry_public_key` configured in `agt.toml`.
- **Validation:** Verification includes signature check, expiry check (`expires_at`), and subject DID matching.

### 2. Fail-Closed Policy (Critical Operations)
- **Definition:** Critical operations include escalation approvals, administrative registrations, and policy enforcement updates.
- **Behavior:** If a valid, fresh attestation cannot be retrieved (e.g., registry unreachable) or fails verification, the operation **must halt** (Fail-Closed). 
- **Rationale:** Stale attestations pose a security risk if an agent has been de-registered or its keys rotated within the 24-hour TTL window.

### 3. Jittered Caching
- **Mechanism:** Clients may cache verified attestations to reduce registry load.
- **Refresh Jitter:** Background refreshes must be jittered (e.g., between 80% and 90% of TTL) to prevent a "thundering herd" effect on the registry when many attestations expire simultaneously.

### 4. Trust Configuration
Trust behavior is governed by a standard structure (stored in `agt.toml` or `trust-policy.yaml`):
```yaml
trust_policy:
  attestation_ttl_max: 86400         # 24 hours
  refresh_before_expiry: 3600        # 1 hour
  fail_closed_on_unreachable: true
  require_fresh_on_escalation: true
```

## Rationale
- **Fail-Closed** is the only safe default for a system managing sensitive privilege escalations.
- **Centralized Root of Trust:** By baking the registry's public key into the client configuration, we avoid circular trust dependencies and provide a clear bootstrap path.

## Deferred / Out of Scope
- **Offline Mode:** Graceful degradation for non-critical operations in fully disconnected environments.
- **OCSP-like Revocation:** Real-time revocation checks are deferred to the 90-day horizon; expiration is the primary revocation mechanism for now.
