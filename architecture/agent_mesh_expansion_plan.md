# AgentMesh Rust Expansion Plan

## 1. Identity & Trust (Core)
- **Status:** Foundations (`AgentIdentity`, `AgentDID`) implemented.
- **Next:**
    - [ ] Implement `CredentialManager` for ephemeral credentials.
    - [ ] Implement `MTLSIdentityVerifier` for secure inter-agent communication.
    - [ ] Implement `RiskScorer` for trust assessment.
    - [ ] Implement `KeyRotationManager` for proactive security.

## 2. Communication Protocols (Transport)
- **Objective:** Implement secure, encrypted channels.
- **Tasks:**
    - [ ] Define transport-agnostic interface (mTLS, Noise protocol).
    - [ ] Implement gateway for protocol bridging (MCP, IATP).
    - [ ] Implement event bus for inter-agent communication.

## 3. Governance & Lifecycle
- **Objective:** Deterministic policy enforcement and automated lifecycle management.
- **Tasks:**
    - [ ] Implement `NamespaceManager` for scope enforcement.
    - [ ] Implement `DelegationLink` for trust delegation chains.
    - [ ] Implement lifecycle hooks (Provisioning -> Revocation).

## 4. Observability & SRE
- **Objective:** Production-grade monitoring and incident response.
- **Tasks:**
    - [ ] Integrate OpenTelemetry for tracing.
    - [ ] Implement circuit breakers for communication stability.

## 5. Verification & Compliance
- **Objective:** Ensure OWASP compliance and benchmark parity.
- **Tasks:**
    - [ ] Create comprehensive suite of integration tests.
    - [ ] Fuzz test core cryptographic and parsing paths.
