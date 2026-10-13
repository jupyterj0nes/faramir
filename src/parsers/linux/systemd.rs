use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses systemd service unit files (*.service) and drop-in configurations
pub fn parse_systemd_service(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    let mut exec_starts = Vec::new();
    let mut user = "root".to_string();
    let mut description = String::new();
    let mut has_section = false;

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            has_section = true;
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("ExecStart=")
            .or_else(|| trimmed.strip_prefix("ExecStartPre="))
            .or_else(|| trimmed.strip_prefix("ExecStartPost="))
            .or_else(|| trimmed.strip_prefix("ExecReload="))
        {
            let val = val.trim();
            if !val.is_empty() {
                exec_starts.push(val.to_string());
            }
        } else if let Some(u) = trimmed.strip_prefix("User=") {
            user = u.trim().to_string();
        } else if let Some(d) = trimmed.strip_prefix("Description=") {
            description = d.trim().to_string();
        }
    }

    if !has_section {
        return Err(LinuxPersistenceError::SystemdMissingUnitSection(file_path.display().to_string()));
    }

    if exec_starts.is_empty() {
        return Err(LinuxPersistenceError::SystemdMissingExec(file_path.display().to_string()));
    }

    let mut events = Vec::new();
    for exec in exec_starts {
        let proc_name = exec
            .trim_start_matches('-')
            .trim_start_matches('@')
            .split_whitespace()
            .next()
            .unwrap_or(&exec)
            .to_string();

        events.push(Event {
            timestamp: fallback_timestamp.clone(),
            computer: computer_name.to_string(),
            artifact: "linux:systemd:service".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: user.clone(),
            target_username: user.clone(),
            processname: proc_name,
            commandline: Some(format!("Systemd Unit: {} (Desc: {}, Exec: {})", filename, description, exec)),
            parentprocessname: "systemd".to_string(),
        });
    }

    Ok(events)
}

/// Parses systemd timer unit files (*.timer)
pub fn parse_systemd_timer(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    let mut schedule = String::new();
    let mut unit_target = String::new();
    let mut has_section = false;

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            has_section = true;
            continue;
        }

        if let Some(cal) = trimmed.strip_prefix("OnCalendar=") {
            schedule = format!("OnCalendar: {}", cal.trim());
        } else if let Some(boot) = trimmed.strip_prefix("OnBootSec=") {
            schedule = format!("OnBootSec: {}", boot.trim());
        } else if let Some(act) = trimmed.strip_prefix("OnActiveSec=") {
            schedule = format!("OnActiveSec: {}", act.trim());
        } else if let Some(u) = trimmed.strip_prefix("Unit=") {
            unit_target = u.trim().to_string();
        }
    }

    if !has_section {
        return Err(LinuxPersistenceError::SystemdMissingUnitSection(file_path.display().to_string()));
    }

    if schedule.is_empty() {
        return Err(LinuxPersistenceError::SystemdMissingExec(file_path.display().to_string()));
    }

    let target = if unit_target.is_empty() {
        filename.replace(".timer", ".service")
    } else {
        unit_target
    };

    Ok(vec![Event {
        timestamp: fallback_timestamp,
        computer: computer_name.to_string(),
        artifact: "linux:systemd:timer".to_string(),
        event_id: 0,
        pid: 0,
        subject_username: "root".to_string(),
        target_username: "root".to_string(),
        processname: target.clone(),
        commandline: Some(format!("Systemd Timer: {} -> {} ({})", filename, target, schedule)),
        parentprocessname: "systemd".to_string(),
    }])
}

/// Parses systemd socket or path activation files (*.socket, *.path)
pub fn parse_systemd_socket_or_path(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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
    let is_socket = filename.ends_with(".socket");
    let reader = BufReader::new(file);

    let mut trigger = String::new();
    let mut has_section = false;

    for line_res in reader.lines() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            has_section = true;
            continue;
        }

        if let Some(_listen) = trimmed.strip_prefix("ListenStream=")
            .or_else(|| trimmed.strip_prefix("ListenDatagram="))
            .or_else(|| trimmed.strip_prefix("PathModified="))
            .or_else(|| trimmed.strip_prefix("PathExists="))
        {
            trigger = trimmed.to_string();
        }
    }

    if !has_section {
        return Err(LinuxPersistenceError::SystemdMissingUnitSection(file_path.display().to_string()));
    }

    if trigger.is_empty() {
        return Err(LinuxPersistenceError::SystemdMissingExec(file_path.display().to_string()));
    }

    let artifact = if is_socket { "linux:systemd:socket" } else { "linux:systemd:path" };

    Ok(vec![Event {
        timestamp: fallback_timestamp,
        computer: computer_name.to_string(),
        artifact: artifact.to_string(),
        event_id: 0,
        pid: 0,
        subject_username: "root".to_string(),
        target_username: "root".to_string(),
        processname: filename.to_string(),
        commandline: Some(format!("Systemd Activation [{}]: {}", filename, trigger)),
        parentprocessname: "systemd".to_string(),
    }])
}

/// Parses systemd generators (/etc/systemd/system-generators/*)
pub fn parse_systemd_generator(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
    if !file_path.exists() {
        return Err(LinuxPersistenceError::FileNotFound(file_path.display().to_string()));
    }

    let metadata = fs::metadata(file_path)?;
    let fallback_timestamp = metadata
        .modified()
        .ok()
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    Ok(vec![Event {
        timestamp: fallback_timestamp,
        computer: computer_name.to_string(),
        artifact: "linux:systemd:generator".to_string(),
        event_id: 0,
        pid: 0,
        subject_username: "root".to_string(),
        target_username: "root".to_string(),
        processname: filename.to_string(),
        commandline: Some(format!("Systemd Generator Executable: {}", file_path.display())),
        parentprocessname: "systemd".to_string(),
    }])
}
