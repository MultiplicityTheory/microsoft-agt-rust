use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use agent_mesh_core::identity::PrivilegeRing;
use agent_mesh_core::audit::{DataCategory, ActionLogRecord, ActionOutcome};
use agent_mesh_core::identity::EscalationEvent;
use uuid::Uuid;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write, BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use anyhow::{Result, anyhow};
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActionRecord {
    pub action: String,
    pub timestamp: chrono::DateTime<Utc>,
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

    pub fn replay_since(&self, since: chrono::DateTime<Utc>) -> Result<Vec<ActionLogRecord>> {
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

#[async_trait]
pub trait SiemExporter: Send + Sync {
    async fn export_action(&self, record: &ActionLogRecord) -> Result<()>;
    async fn export_escalation(&self, event: &EscalationEvent) -> Result<()>;
}

pub struct HttpSiemExporter {
    endpoint: String,
    token: String,
    client: reqwest::Client,
}

impl HttpSiemExporter {
    pub fn new(endpoint: String, token: String) -> Self {
        Self {
            endpoint,
            token,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SiemExporter for HttpSiemExporter {
    async fn export_action(&self, record: &ActionLogRecord) -> Result<()> {
        let response = self.client.post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-AGT-Event-Type", "action")
            .json(record)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("SIEM export failed with status: {}", response.status()))
        }
    }

    async fn export_escalation(&self, event: &EscalationEvent) -> Result<()> {
        let response = self.client.post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-AGT-Event-Type", "escalation")
            .json(event)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("SIEM export failed with status: {}", response.status()))
        }
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
}
