use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses SSH authorized_keys file
pub fn parse_ssh_authorized_keys(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    // Extract username from path (/home/<username>/.ssh/authorized_keys or /root/.ssh/authorized_keys)
    let user = file_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "user".to_string());

    let reader = BufReader::new(file);
    let mut events = Vec::new();

    let valid_types = [
        "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
    ];

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // Line might start with options, e.g. command="dump.sh",from="1.2.3.4" ssh-rsa AAA... comment
        let key_type_idx = tokens.iter().position(|t| valid_types.contains(t));

        if let Some(idx) = key_type_idx {
            let key_type = tokens[idx];
            let comment = tokens.get(idx + 2..).map(|s| s.join(" ")).unwrap_or_default();
            let options = if idx > 0 { tokens[..idx].join(" ") } else { String::new() };

            let mut details = format!("SSH Key ({}) Comment: {}", key_type, comment);
            if !options.is_empty() {
                details.push_str(&format!(" [Options: {}]", options));
            }

            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:ssh:authorized_key".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: user.clone(),
                target_username: user.clone(),
                processname: "sshd".to_string(),
                commandline: Some(details),
                parentprocessname: "sshd".to_string(),
            });
        } else {
            return Err(LinuxPersistenceError::SshKeyInvalid(format!(
                "line {}: unknown or malformed key type",
                line_idx + 1
            )));
        }
    }

    Ok(events)
}

/// Parses /etc/ssh/sshd_config for backdoor configurations
pub fn parse_sshd_config(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        let key = tokens[0];
        let val = tokens[1..].join(" ");

        if key.eq_ignore_ascii_case("AuthorizedKeysCommand") && !val.eq_ignore_ascii_case("none") {
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:ssh:authorized_keys_command".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: tokens.get(1).unwrap_or(&"sshd").to_string(),
                commandline: Some(format!("sshd_config [line {}]: AuthorizedKeysCommand {}", line_idx + 1, val)),
                parentprocessname: "sshd".to_string(),
            });
        } else if key.eq_ignore_ascii_case("ForceCommand") && !val.eq_ignore_ascii_case("none") {
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:ssh:force_command".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: "root".to_string(),
                target_username: "root".to_string(),
                processname: tokens.get(1).unwrap_or(&"sshd").to_string(),
                commandline: Some(format!("sshd_config [line {}]: ForceCommand {}", line_idx + 1, val)),
                parentprocessname: "sshd".to_string(),
            });
        }
    }

    Ok(events)
}
