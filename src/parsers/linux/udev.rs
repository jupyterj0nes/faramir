use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses udev rule files in /etc/udev/rules.d/*
pub fn parse_udev_rule_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

        // Check for RUN+= action
        if let Some(pos) = trimmed.find("RUN+=") {
            let action_part = &trimmed[pos + 5..];
            let clean_cmd = action_part.trim_matches(|c| c == '"' || c == '\'' || c == ' ');
            let proc_name = clean_cmd.split_whitespace().next().unwrap_or(clean_cmd).to_string();

            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:udev:run_action".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: proc_name,
                commandline: Some(format!("Udev [{} line {}]: {}", filename, line_idx + 1, trimmed)),
                parentprocessname: "udevd".to_string(),
            });
        }
    }

    Ok(events)
}
