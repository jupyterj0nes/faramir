use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Checks if a shell line has persistence or backdoor indicators
pub fn evaluate_shell_line(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    if trimmed.contains("/dev/tcp/") || trimmed.contains("/dev/udp/") {
        return Some("bash_socket_reverse_shell");
    }
    if trimmed.contains("bash -i") || trimmed.contains("sh -i") || trimmed.contains("zsh -i") {
        return Some("interactive_shell_spawn");
    }
    if trimmed.contains("nc ") || trimmed.contains("ncat ") || trimmed.contains("netcat ") {
        return Some("netcat_network_execution");
    }
    if trimmed.contains("curl ") && (trimmed.contains("| bash") || trimmed.contains("| sh") || trimmed.contains("-o /tmp") || trimmed.contains("-o /dev/shm")) {
        return Some("curl_piped_or_download_exec");
    }
    if trimmed.contains("wget ") && (trimmed.contains("| bash") || trimmed.contains("| sh") || trimmed.contains("-O /tmp") || trimmed.contains("-O /dev/shm")) {
        return Some("wget_piped_or_download_exec");
    }
    if trimmed.contains("base64 -d") || trimmed.contains("base64 --decode") {
        return Some("base64_encoded_payload");
    }
    if trimmed.contains("python -c") || trimmed.contains("python3 -c") || trimmed.contains("perl -e") || trimmed.contains("ruby -e") || trimmed.contains("php -r") {
        return Some("one_liner_interpreter_payload");
    }
    if trimmed.starts_with("export PATH=") && (trimmed.contains("/tmp") || trimmed.contains("/dev/shm") || trimmed.starts_with("export PATH=.:") || trimmed.contains(":. :")) {
        return Some("path_environment_hijack");
    }
    if trimmed.starts_with("alias sudo=") || trimmed.starts_with("alias su=") || trimmed.starts_with("alias ssh=") {
        return Some("credential_harvesting_alias");
    }
    if (trimmed.contains("/tmp/") || trimmed.contains("/dev/shm/") || trimmed.contains("/var/tmp/")) && (trimmed.contains(".sh") || trimmed.contains("./") || trimmed.ends_with('&')) {
        return Some("temp_directory_script_execution");
    }

    None
}

/// Parses shell profile or RC script (/etc/profile, ~/.bashrc, rc.local, etc.)
pub fn parse_shell_script(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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
    let is_rc_local = filename == "rc.local";
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if is_rc_local {
            // In rc.local, every non-comment command executes on boot with root privilege!
            if trimmed != "exit 0" {
                let proc_name = trimmed.split_whitespace().next().unwrap_or("rc.local").to_string();
                events.push(Event {
                    timestamp: fallback_timestamp.clone(),
                    computer: computer_name.to_string(),
                    artifact: "linux:boot:rc_local".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: "root".to_string(),
                    target_username: "root".to_string(),
                    processname: proc_name,
                    commandline: Some(format!("rc.local [line {}]: {}", line_idx + 1, trimmed)),
                    parentprocessname: "init".to_string(),
                });
            }
        } else if let Some(indicator) = evaluate_shell_line(trimmed) {
            let proc_name = trimmed.split_whitespace().next().unwrap_or(filename).to_string();
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: format!("linux:shell:{}", indicator),
                event_id: 0,
                pid: 0,
                subject_username: "user".to_string(),
                target_username: "user".to_string(),
                processname: proc_name,
                commandline: Some(format!("{} [line {}]: {}", filename, line_idx + 1, trimmed)),
                parentprocessname: "shell".to_string(),
            });
        }
    }

    Ok(events)
}
