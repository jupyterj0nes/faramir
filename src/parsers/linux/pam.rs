use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses PAM configuration files in /etc/pam.d/*
pub fn parse_pam_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
    if !file_path.exists() {
        return Err(LinuxPersistenceError::FileNotFound(file_path.display().to_string()));
    }

    let file = File::open(file_path)?;
    let metadata = fs::metadata(file_path)?;
    if metadata.len() == 0 {
        return Err(LinuxPersistenceError::EmptyFile(file_path.display().to_string()));
    }

    let fallback_timestamp = metadata
        .modified()
        .ok()
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        let module_type = tokens[0];
        let control = tokens[1];
        let module_path = tokens[2];
        let args = tokens[3..].join(" ");

        if module_path.contains("pam_exec.so") {
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:pam:exec_backdoor".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: "pam_exec.so".to_string(),
                commandline: Some(format!("PAM [{} line {}]: {} {} {} {}", filename, line_idx + 1, module_type, control, module_path, args)),
                parentprocessname: "pam".to_string(),
            });
        } else if module_path.contains("pam_permit.so") && (module_type == "auth" || module_type == "account") {
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:pam:permit_bypass".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: "pam_permit.so".to_string(),
                commandline: Some(format!("PAM Bypass [{} line {}]: {} {} {}", filename, line_idx + 1, module_type, control, module_path)),
                parentprocessname: "pam".to_string(),
            });
        } else if module_path.starts_with('/') && !module_path.starts_with("/lib/security")
            && !module_path.starts_with("/lib64/security")
            && !module_path.starts_with("/usr/lib/security")
            && !module_path.starts_with("/usr/lib64/security")
        {
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:pam:custom_module_path".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: module_path.to_string(),
                commandline: Some(format!("PAM Rogue Module [{} line {}]: {}", filename, line_idx + 1, trimmed)),
                parentprocessname: "pam".to_string(),
            });
        }
    }

    Ok(events)
}
