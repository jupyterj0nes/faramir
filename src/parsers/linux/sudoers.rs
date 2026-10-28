use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses /etc/sudoers and /etc/sudoers.d/* files
pub fn parse_sudoers_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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
            dt.format(crate::windows::techniques::FORMAT_DATE).to_string()
        })
        .unwrap_or_else(|| "1970-01-01 00:00:00.000".to_string());

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check for NOPASSWD or !authenticate or ALL privesc
        if trimmed.contains("NOPASSWD:") || trimmed.contains("!authenticate") {
            let user = trimmed.split_whitespace().next().unwrap_or("unknown");
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:sudoers:nopasswd".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: user.to_string(),
                target_username: "root".to_string(),
                processname: "sudo".to_string(),
                commandline: Some(format!("Sudoers [{} line {}]: {}", filename, line_idx + 1, trimmed)),
                parentprocessname: "sudo".to_string(),
            });
        } else if trimmed.starts_with("Defaults") && (trimmed.contains("env_keep") || trimmed.contains("!lecture")) {
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:sudoers:defaults_override".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: "sudo".to_string(),
                commandline: Some(format!("Sudoers Defaults [{} line {}]: {}", filename, line_idx + 1, trimmed)),
                parentprocessname: "sudo".to_string(),
            });
        }
    }

    Ok(events)
}
