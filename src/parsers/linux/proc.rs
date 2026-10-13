use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses running processes output or /proc/*/exe listings
pub fn parse_running_processes_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Format typically from ls -l /proc/*/exe:
        // lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/10615/exe -> /bin/bash (deleted)
        if trimmed.contains("-> ") {
            let parts: Vec<&str> = trimmed.split("-> ").collect();
            if parts.len() >= 2 {
                let target = parts[1].trim();

                let is_deleted = target.contains("(deleted)");
                let is_suspicious_path = target.starts_with("/tmp/") || target.starts_with("/dev/shm/")
                    || target.starts_with("/var/tmp/") || target.starts_with("/run/shm/");

                if is_deleted || is_suspicious_path {
                    let pid_part = parts[0].split("/proc/").nth(1).and_then(|s| s.split('/').next()).unwrap_or("0");
                    let pid: u32 = pid_part.parse().unwrap_or(0);

                    let artifact_label = if is_deleted {
                        "linux:process:deleted_binary_in_memory"
                    } else {
                        "linux:process:temp_path_execution"
                    };

                    events.push(Event {
                        timestamp: fallback_timestamp.clone(),
                        computer: computer_name.to_string(),
                        artifact: artifact_label.to_string(),
                        event_id: 0,
                        pid,
                        subject_username: "root".to_string(),
                        target_username: "root".to_string(),
                        processname: target.split_whitespace().next().unwrap_or(target).to_string(),
                        commandline: Some(format!("Executing Binary Link: {}", target)),
                        parentprocessname: "proc".to_string(),
                    });
                }
            }
        }
    }

    Ok(events)
}
