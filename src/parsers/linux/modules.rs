use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses /etc/modules, /etc/modules-load.d/*.conf, /etc/modprobe.d/*.conf
pub fn parse_kernel_modules_config(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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
    let is_modprobe = filename.ends_with(".conf") && file_path.to_string_lossy().contains("modprobe.d");
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if is_modprobe {
            // Check for install directive: install <module> <command>
            if trimmed.starts_with("install ") {
                let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                if tokens.len() >= 3 {
                    let mod_name = tokens[1];
                    let cmd = tokens[2..].join(" ");
                    events.push(Event {
                        timestamp: fallback_timestamp.clone(),
                        computer: computer_name.to_string(),
                        artifact: "linux:modprobe:install_command".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: "root".to_string(),
                        target_username: "root".to_string(),
                        processname: mod_name.to_string(),
                        commandline: Some(format!("Modprobe Install Hook [{} line {}]: {}", filename, line_idx + 1, cmd)),
                        parentprocessname: "modprobe".to_string(),
                    });
                }
            }
        } else {
            // General /etc/modules line: module_name [options]
            let mod_name = trimmed.split_whitespace().next().unwrap_or(trimmed);
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:kernel:module_load".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: mod_name.to_string(),
                commandline: Some(format!("Kernel Auto-load Module: {} (File: {})", mod_name, filename)),
                parentprocessname: "kernel".to_string(),
            });
        }
    }

    Ok(events)
}
