# ADR-001: Storage Backends and Security Architecture

## Status
Proposed / Accepted (Sprint 4)

## Context
The Microsoft-AGT Rust port requires durable storage for agent identities (private keys) and governance policies. In a distributed-ready model, these stores must be portable, resilient to corruption, and secure against local compromise.

## Decisions

### 1. Encrypted `FileKeyStore`
- **Mechanism:** Private keys are encrypted at rest using `XChaCha20Poly1305` (Aead).
- **Key Derivation:** A Key-Encryption-Key (KEK) is derived from a user-provided passphrase via `Argon2id` at runtime.
- **Provenance:** The passphrase is provided via the `AGT_KEY_PASSPHRASE` environment variable.
- **Format:** One JSON file per agent DID (hashed filename), containing a per-file salt, nonce, and ciphertext.

### 2. Atomic `FilePolicyStore`
- **Mechanism:** Governance policies are stored as JSON files.
- **Resilience:** All writes follow the "write-to-tmp-then-rename" pattern to ensure atomicity and prevent data corruption during crashes.
- **Format:** One JSON file per agent DID (hashed filename).

### 3. Structured Audit Logging
- **Mechanism:** Privilege escalation events are logged in JSONL (JSON Lines) format.
- **Integrity:** The `EscalationManager` flushes the log buffer after every write to ensure that no audit record is lost in a crash.
- **Serialization:** Enum types (like `PrivilegeRing`) are serialized as strings to ensure human readability and forward compatibility.

## Rationale
- **Argon2id** was chosen as the KDF because it is the industry standard for password-based key derivation, offering superior resistance to GPU/ASIC-based cracking compared to PBKDF2 or scrypt.
- **XChaCha20Poly1305** provides high-performance, misuse-resistant authenticated encryption with a large nonce space, suitable for distributed systems where collision resistance is critical.
- **Atomic Renames** leverage filesystem-level guarantees to ensure that a partial write never results in a corrupted policy.

## Deferred / Out of Scope
- **Passphrase Rotation:** Coordinated re-encryption of the store is deferred to the KMS migration phase.
- **KMS Integration:** Native integration with AWS KMS or HashiCorp Vault is planned for the 90-day horizon.
- **Network Adapters:** Implementing `KeyStore` and `PolicyStore` over gRPC/HTTP is planned for Sprint 5.

## Security Considerations
- The current implementation relies on the security of the environment variable `AGT_KEY_PASSPHRASE`. 
- While encryption at rest protects against disk theft, a running process with the KEK in memory remains a target. This risk is inherent in the "passphrase-derived" model and will be mitigated by the transition to hardware-backed KMS.
