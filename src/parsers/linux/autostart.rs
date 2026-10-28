use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses XDG autostart .desktop files
pub fn parse_xdg_desktop_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    let mut exec = String::new();
    let mut name = String::new();
    let mut hidden = false;
    let mut has_entry_section = false;

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed == "[Desktop Entry]" {
            has_entry_section = true;
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("Exec=") {
            exec = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("Name=") {
            name = val.trim().to_string();
        } else if let Some(val) = trimmed.strip_prefix("Hidden=") {
            if val.trim().eq_ignore_ascii_case("true") {
                hidden = true;
            }
        }
    }

    if !has_entry_section {
        return Err(LinuxPersistenceError::XdgSyntax(format!("{}: missing [Desktop Entry] section", filename)));
    }

    if exec.is_empty() {
        return Err(LinuxPersistenceError::XdgMissingExec(file_path.display().to_string()));
    }

    if hidden {
        // Disabled entry
        return Ok(vec![]);
    }

    let proc_name = exec.split_whitespace().next().unwrap_or(&exec).to_string();

    Ok(vec![Event {
        timestamp: fallback_timestamp,
        computer: computer_name.to_string(),
        artifact: "linux:xdg:autostart".to_string(),
        event_id: 0,
        pid: 0,
        subject_username: "user".to_string(),
        target_username: "user".to_string(),
        processname: proc_name,
        commandline: Some(format!("XDG Autostart: {} ({}) -> {}", filename, name, exec)),
        parentprocessname: "xdg-autostart".to_string(),
    }])
}
