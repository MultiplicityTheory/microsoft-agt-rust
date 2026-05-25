use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use agent_mesh_core::identity::PrivilegeRing;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write, BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use anyhow::{Result, anyhow};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DataCategory {
    PersonalData,           // GDPR scope
    FinancialRecord,        // SOX scope
    AuditLog,               // both
    SystemConfig,           // neither
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActionRecord {
    pub action: String,
    pub timestamp: DateTime<Utc>,
    pub resource_category: DataCategory,
}

#[derive(Debug, Clone)]
pub struct ComplianceInput {
    pub agent_did: String,
    pub agent_ring: PrivilegeRing,
    pub agent_capabilities: Vec<String>,
    pub action: String,
    pub resource_category: DataCategory,
    pub action_history: Vec<ActionRecord>,
    pub jurisdiction: Option<String>, // "EU", "US", None
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ComplianceResult {
    Compliant,
    NotApplicable,
    Violation { rule: String, reason: String },
}

pub trait ComplianceRule {
    fn name(&self) -> String;
    fn evaluate(&self, input: &ComplianceInput) -> ComplianceResult;
}

/// GDPR Data Export Rule
pub struct GdprDataExportRule;

impl ComplianceRule for GdprDataExportRule {
    fn name(&self) -> String { "GDPR-001".to_string() }

    fn evaluate(&self, input: &ComplianceInput) -> ComplianceResult {
        if input.action != "data_export" { return ComplianceResult::NotApplicable; }
        if input.resource_category != DataCategory::PersonalData { return ComplianceResult::NotApplicable; }
        if input.jurisdiction.as_deref() == Some("US") { return ComplianceResult::NotApplicable; }

        if !input.agent_capabilities.contains(&"gdpr_data_processor".to_string()) {
            return ComplianceResult::Violation {
                rule: self.name(),
                reason: "Agent lacks gdpr_data_processor capability for PersonalData export".to_string(),
            };
        }
        ComplianceResult::Compliant
    }
}

/// SOX Audit Log Immutability Rule
pub struct SoxAuditImmutabilityRule {
    pub isolation_window: Duration,
}

impl ComplianceRule for SoxAuditImmutabilityRule {
    fn name(&self) -> String { "SOX-001".to_string() }

    fn evaluate(&self, input: &ComplianceInput) -> ComplianceResult {
        if input.resource_category != DataCategory::AuditLog { return ComplianceResult::NotApplicable; }
        if !["read", "read_audit_log"].contains(&input.action.as_str()) { return ComplianceResult::NotApplicable; }

        let cutoff = Utc::now() - self.isolation_window;
        let recent_write = input.action_history.iter().any(|r| {
            r.timestamp > cutoff
            && matches!(r.resource_category, DataCategory::FinancialRecord | DataCategory::AuditLog)
            && (r.action.starts_with("write") || r.action.starts_with("delete") || r.action.starts_with("update"))
        });

        if recent_write {
            return ComplianceResult::Violation {
                rule: self.name(),
                reason: format!("Agent has recent write history within window ({:?}); audit log read denied", self.isolation_window),
            };
        }
        ComplianceResult::Compliant
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActionLogRecord {
    pub record_id: Uuid,
    pub agent_did: String,
    pub action: String,
    pub resource_category: DataCategory,
    pub timestamp: DateTime<Utc>,
    pub outcome: ActionOutcome,
    pub prev_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ActionOutcome {
    Permitted,
    Denied { rule: String, reason: String },
    DiscoveryEvent { event_json: String },
}

impl ActionLogRecord {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct HashableRecord<'a> {
            record_id: Uuid,
            agent_did: &'a str,
            action: &'a str,
            resource_category: &'a DataCategory,
            timestamp: DateTime<Utc>,
            outcome: &'a ActionOutcome,
        }

        let hashable = HashableRecord {
            record_id: self.record_id,
            agent_did: &self.agent_did,
            action: &self.action,
            resource_category: &self.resource_category,
            timestamp: self.timestamp,
            outcome: &self.outcome,
        };

        serde_json::to_vec(&hashable).expect("ActionLogRecord is always serializable")
    }

    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Checkpoint {
    last_hash: String,
    byte_offset: u64,
}

pub struct FileActionLog {
    path: PathBuf,
    checkpoint_path: PathBuf,
    writer: Arc<Mutex<BufWriter<File>>>,
    last_hash: Arc<Mutex<String>>,
}

#[derive(Debug)]
pub struct ChainViolation {
    pub index: usize,
    pub record_id: Uuid,
    pub expected_prev_hash: String,
    pub actual_prev_hash: String,
}

impl FileActionLog {
    pub fn open(path: PathBuf) -> Result<Self> {
        let checkpoint_path = path.with_extension("checkpoint");
        let mut last_hash = "genesis".to_string();
        let mut offset = 0;

        if checkpoint_path.exists() {
            let cp_json = std::fs::read_to_string(&checkpoint_path)?;
            if let Ok(cp) = serde_json::from_str::<Checkpoint>(&cp_json) {
                last_hash = cp.last_hash;
                offset = cp.byte_offset;
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        if offset > 0 {
            file.seek(SeekFrom::Start(offset))?;
        }

        let writer = Arc::new(Mutex::new(BufWriter::new(file)));

        Ok(Self {
            path,
            checkpoint_path,
            writer,
            last_hash: Arc::new(Mutex::new(last_hash)),
        })
    }

    pub fn append(&self, mut record: ActionLogRecord) -> Result<()> {
        let mut lh = self.last_hash.lock().map_err(|_| anyhow!("Lock poisoned"))?;
        record.prev_hash = lh.clone();

        let json = serde_json::to_string(&record)?;
        let mut writer = self.writer.lock().map_err(|_| anyhow!("Lock poisoned"))?;
        
        writer.write_all(json.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;

        *lh = record.compute_hash();

        let offset = writer.get_ref().metadata()?.len();
        let cp = Checkpoint {
            last_hash: lh.clone(),
            byte_offset: offset,
        };
        std::fs::write(&self.checkpoint_path, serde_json::to_string(&cp)?)?;

        Ok(())
    }

    pub fn last_hash(&self) -> String {
        self.last_hash.lock().unwrap().clone()
    }

    pub fn verify_chain(&self) -> Result<Vec<ChainViolation>> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut violations = Vec::new();
        let mut expected_prev_hash = "genesis".to_string();
        
        for (index, line) in reader.lines().enumerate() {
            let line = line?;
            let record: ActionLogRecord = serde_json::from_str(&line)?;
            
            if record.prev_hash != expected_prev_hash {
                violations.push(ChainViolation {
                    index,
                    record_id: record.record_id,
                    expected_prev_hash: expected_prev_hash.clone(),
                    actual_prev_hash: record.prev_hash.clone(),
                });
            }
            
            expected_prev_hash = record.compute_hash();
        }
        
        Ok(violations)
    }

    pub fn load_history(&self, agent_did: &str) -> Result<Vec<ActionRecord>> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut history = Vec::new();
        
        for line in reader.lines() {
            let line = line?;
            let record: ActionLogRecord = serde_json::from_str(&line)?;
            if record.agent_did == agent_did && matches!(record.outcome, ActionOutcome::Permitted) {
                history.push(ActionRecord {
                    action: record.action,
                    timestamp: record.timestamp,
                    resource_category: record.resource_category,
                });
            }
        }
        Ok(history)
    }

    pub fn replay_since(&self, since: DateTime<Utc>) -> Result<Vec<ActionLogRecord>> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        
        for line in reader.lines() {
            let line = line?;
            let record: ActionLogRecord = serde_json::from_str(&line)?;
            if record.timestamp >= since {
                records.push(record);
            }
        }
        Ok(records)
    }
}

pub struct ComplianceVerifier {
    rules: Vec<Box<dyn ComplianceRule + Send + Sync>>,
}

impl ComplianceVerifier {
    pub fn new(rules: Vec<Box<dyn ComplianceRule + Send + Sync>>) -> Self {
        Self { rules }
    }

    pub fn default_policy() -> Self {
        Self {
            rules: vec![
                Box::new(GdprDataExportRule),
                Box::new(SoxAuditImmutabilityRule { isolation_window: Duration::hours(24) }),
            ],
        }
    }

    pub fn evaluate(&self, input: &ComplianceInput) -> Vec<ComplianceResult> {
        self.rules.iter().map(|r| r.evaluate(input)).collect()
    }

    pub fn is_compliant(&self, input: &ComplianceInput) -> bool {
        self.evaluate(input).iter().all(|r| !matches!(r, ComplianceResult::Violation { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mock_input() -> ComplianceInput {
        ComplianceInput {
            agent_did: "did:mesh:test".to_string(),
            agent_ring: PrivilegeRing::Standard,
            agent_capabilities: vec![],
            action: "read".to_string(),
            resource_category: DataCategory::SystemConfig,
            action_history: vec![],
            jurisdiction: None,
        }
    }

    #[test]
    fn test_action_log_hash_chain() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("action.jsonl");
        let log = FileActionLog::open(log_path.clone()).unwrap();

        let record1 = ActionLogRecord {
            record_id: Uuid::new_v4(),
            agent_did: "agent-1".to_string(),
            action: "read".to_string(),
            resource_category: DataCategory::PersonalData,
            timestamp: Utc::now(),
            outcome: ActionOutcome::Permitted,
            prev_hash: "".to_string(),
        };

        log.append(record1).unwrap();
        let hash1 = log.last_hash();
        assert_ne!(hash1, "genesis");

        let record2 = ActionLogRecord {
            record_id: Uuid::new_v4(),
            agent_did: "agent-1".to_string(),
            action: "write".to_string(),
            resource_category: DataCategory::FinancialRecord,
            timestamp: Utc::now(),
            outcome: ActionOutcome::Permitted,
            prev_hash: "".to_string(),
        };

        log.append(record2).unwrap();
        
        let violations = log.verify_chain().unwrap();
        assert!(violations.is_empty());

        let log_reopened = FileActionLog::open(log_path).unwrap();
        assert_eq!(log_reopened.last_hash(), log.last_hash());
    }

    #[test]
    fn test_tamper_detection() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("action.jsonl");
        let log = FileActionLog::open(log_path.clone()).unwrap();

        log.append(ActionLogRecord {
            record_id: Uuid::new_v4(),
            agent_did: "agent-1".to_string(),
            action: "action-1".to_string(),
            resource_category: DataCategory::SystemConfig,
            timestamp: Utc::now(),
            outcome: ActionOutcome::Permitted,
            prev_hash: "".to_string(),
        }).unwrap();

        log.append(ActionLogRecord {
            record_id: Uuid::new_v4(),
            agent_did: "agent-1".to_string(),
            action: "action-2".to_string(),
            resource_category: DataCategory::SystemConfig,
            timestamp: Utc::now(),
            outcome: ActionOutcome::Permitted,
            prev_hash: "".to_string(),
        }).unwrap();

        let mut content = std::fs::read_to_string(&log_path).unwrap();
        content = content.replace("action-1", "action-X");
        std::fs::write(&log_path, content).unwrap();

        let violations = log.verify_chain().unwrap();
        assert!(!violations.is_empty());
    }
}
