use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Is a `pam_permit.so` line a bypass rather than the stock stack closer?
///
/// Debian and Ubuntu end every `auth` / `account` stack in `common-*` with
/// `required pam_permit.so` to prime a success code once `pam_unix` /
/// `pam_sss` / `pam_deny` above it have had their say; that line decides
/// nothing. A `pam_permit` placed *first* in its stack, or one with a
/// control that ends the stack with success (`sufficient`, `[success=done …]`,
/// `[success=ok …]`), lets anyone through.
pub fn pam_permit_is_bypass(control: &str, first_of_stack: bool) -> bool {
    if first_of_stack {
        return true;
    }
    let c = control.to_ascii_lowercase();
    c == "sufficient" || c == "binding" || (c.starts_with('[') && (c.contains("success=done") || c.contains("success=ok")))
}

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
            dt.format(crate::windows::techniques::FORMAT_DATE).to_string()
        })
        .unwrap_or_else(|| "1970-01-01 00:00:00.000".to_string());

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    // module types that already have a line above the current one
    let mut seen_type: std::collections::HashSet<String> = std::collections::HashSet::new();

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

        let module_type = tokens[0].trim_start_matches('-');
        // a bracketed control (`[success=1 default=ignore]`) spans several tokens
        let control_end = if tokens[1].starts_with('[') {
            match tokens.iter().position(|t| t.ends_with(']')) {
                Some(i) => i + 1,
                None => continue,
            }
        } else {
            2
        };
        if tokens.len() <= control_end {
            continue;
        }
        let control_owned = tokens[1..control_end].join(" ");
        let control = control_owned.as_str();
        let module_path = tokens[control_end];
        let args = tokens[control_end + 1..].join(" ");
        let first_of_stack = seen_type.insert(module_type.to_ascii_lowercase());

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
        } else if module_path.contains("pam_permit.so")
            && (module_type == "auth" || module_type == "account")
            && pam_permit_is_bypass(control, first_of_stack)
        {
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
