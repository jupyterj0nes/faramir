use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses APT configuration hook files in /etc/apt/apt.conf.d/*
pub fn parse_apt_hook_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // APT hooks typically look like: APT::Update::Post-Invoke {"/bin/sh -c '...'"};
        if trimmed.contains("::Post-Invoke") || trimmed.contains("::Pre-Invoke") || trimmed.contains("::Pre-Install-Pkgs") {
            let cmd_part = trimmed
                .split('{')
                .nth(1)
                .and_then(|s| s.split('}').next())
                .unwrap_or(trimmed)
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');

            let proc_name = cmd_part.split_whitespace().next().unwrap_or("apt").to_string();

            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:apt:package_hook".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: proc_name,
                commandline: Some(format!("APT Hook [{} line {}]: {}", filename, line_idx + 1, trimmed)),
                parentprocessname: "apt".to_string(),
            });
        }
    }

    Ok(events)
}
