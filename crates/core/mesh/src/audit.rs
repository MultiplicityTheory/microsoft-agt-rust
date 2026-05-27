use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use sha2::{Sha256, Digest};

use std::str::FromStr;
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DataCategory {
    PersonalData,           // GDPR scope
    FinancialRecord,        // SOX scope
    AuditLog,               // both
    SystemConfig,           // neither
    Unknown,
}

impl FromStr for DataCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "personaldata" | "personal_data" | "pii" => Ok(DataCategory::PersonalData),
            "financialrecord" | "financial_record" | "sox" => Ok(DataCategory::FinancialRecord),
            "auditlog" | "audit_log" => Ok(DataCategory::AuditLog),
            "systemconfig" | "system_config" => Ok(DataCategory::SystemConfig),
            "unknown" => Ok(DataCategory::Unknown),
            _ => Err(format!("Unknown data category: {}", s)),
        }
    }
}

impl fmt::Display for DataCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataCategory::PersonalData => write!(f, "PersonalData"),
            DataCategory::FinancialRecord => write!(f, "FinancialRecord"),
            DataCategory::AuditLog => write!(f, "AuditLog"),
            DataCategory::SystemConfig => write!(f, "SystemConfig"),
            DataCategory::Unknown => write!(f, "Unknown"),
        }
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
