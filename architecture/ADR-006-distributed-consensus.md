# ADR-006: Distributed Consensus and Registry Reliability

## Status
Proposed

## Context
The AGT daemon currently stores agent registration state in memory. While `FileAgentRegistry` provides a mechanism for local persistence (JSONL), it does not address the need for high availability or consistency across multiple daemon instances.

We need to decide on the architecture for distributed consensus to support:
1. **Write Consistency**: Multiple daemons must agree on the registry state.
2. **Read Availability**: Agents must be able to verify attestations even if a specific daemon instance is down.
3. **Disaster Recovery**: The registry must survive permanent host failure.

Three scenarios were considered:
- **Scenario A (Full Raft)**: Implement the Raft consensus protocol using a library like `openraft`.
- **Scenario B (Local Persistence)**: Single authoritative daemon with file-backed storage.
- **Scenario C (External Store / Standby)**: Use an external consistent store (e.g., etcd, Postgres) or a primary/standby model with health-check-based failover.

## Decision
We will prioritize **Scenario B (Local Persistence)** as the immediate baseline for reliability (Sprint 11), followed by an evaluation of **Scenario C (External Store)** for multi-node deployments.

We will **defer** the implementation of a full Raft consensus protocol (Scenario A) because:
1. **Complexity**: Raft implementation is a 90-day engineering effort involving log management, cluster membership, and leader election.
2. **Quorum Requirements**: A 2-node cluster (common in smaller deployments) cannot provide Raft quorum; it requires at least 3 nodes to tolerate 1 failure.
3. **Operational Overhead**: Managed consensus stores (like etcd) or simpler failover mechanisms provide similar benefits with significantly lower implementation and maintenance costs.

### Phased Roadmap
1. **Sprint 11 (Persistence)**: Finalize `FileAgentRegistry` and integrate it into the daemon. Ensure the registry survives process restarts.
2. **Sprint 12 (Centralized Consensus)**: Implement an `EtcdAgentRegistry` or similar adapter for deployments requiring multi-node write consistency.
3. **Future**: Re-evaluate custom Raft implementation only if external dependencies (etcd/DB) are strictly prohibited in the target environment.

## Failure Scenarios Handled
- **Daemon Crash**: Solved by Scenario B (File-backed storage).
- **Host Failure**: Solved by Scenario C (External store or shared volume).
- **Network Partition**: Solved by Scenario C (Consistent store quorum).

## Alternatives Considered
- **Raft (openraft)**: High complexity, high control. Rejected for initial MVP.
- **etcd**: Industry standard for distributed configuration. Preferred for multi-node.
- **Postgres (with row-level locking)**: Suitable if a DB is already available.
