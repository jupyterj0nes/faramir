use serde::{Deserialize, Serialize};

/// Structure for an extracted event/persistence item matching Caarea & Masstin standard formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: String,
    pub computer: String,
    pub artifact: String,
    pub event_id: u64,
    pub pid: u32,
    pub subject_username: String,
    pub target_username: String,
    pub processname: String,
    pub commandline: Option<String>,
    pub parentprocessname: String,
}
