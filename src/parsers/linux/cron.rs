use crate::event::Event;
use crate::parsers::linux::error::LinuxPersistenceError;
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parses system cron files (/etc/crontab, /etc/cron.d/*)
pub fn parse_cron_system_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("SHELL=")
            || trimmed.starts_with("PATH=") || trimmed.starts_with("MAILTO=") || trimmed.starts_with("HOME=")
        {
            continue;
        }

        // Format: min hour dom mon dow USER command
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 7 {
            return Err(LinuxPersistenceError::InvalidCronSyntax(format!(
                "{}:{}: expected at least 7 fields, got {}",
                filename,
                line_idx + 1,
                tokens.len()
            )));
        }

        let user = tokens[5].to_string();
        let cmd_tokens = &tokens[6..];
        let command = cmd_tokens.join(" ");
        let proc_name = cmd_tokens.first().unwrap_or(&"cron").to_string();

        events.push(Event {
            timestamp: fallback_timestamp.clone(),
            computer: computer_name.to_string(),
            artifact: "linux:cron:system_job".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: user.clone(),
            target_username: user,
            processname: proc_name,
            commandline: Some(format!("System Cron: {} (File: {})", command, filename)),
            parentprocessname: "crond".to_string(),
        });
    }

    Ok(events)
}

/// Parses user cron files in spool (/var/spool/cron/*, /var/spool/cron/crontabs/*)
pub fn parse_cron_spool_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    let user = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| LinuxPersistenceError::IoError(e.to_string()))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("SHELL=")
            || trimmed.starts_with("PATH=") || trimmed.starts_with("MAILTO=") || trimmed.starts_with("HOME=")
        {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens[0].starts_with('@') {
            if tokens.len() < 2 {
                return Err(LinuxPersistenceError::MissingCronCommand(format!(
                    "{}:{}: special interval {} without command",
                    user,
                    line_idx + 1,
                    tokens[0]
                )));
            }
            let command = tokens[1..].join(" ");
            let proc_name = tokens.get(1).unwrap_or(&"cron").to_string();
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:cron:user_spool".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: user.clone(),
                target_username: user.clone(),
                processname: proc_name,
                commandline: Some(format!("User Cron {}: {}", tokens[0], command)),
                parentprocessname: "crond".to_string(),
            });
        } else {
            // min hour dom mon dow command
            if tokens.len() < 6 {
                return Err(LinuxPersistenceError::InvalidCronSyntax(format!(
                    "{}:{}: expected at least 6 fields, got {}",
                    user,
                    line_idx + 1,
                    tokens.len()
                )));
            }
            let command = tokens[5..].join(" ");
            let proc_name = tokens.get(5).unwrap_or(&"cron").to_string();
            events.push(Event {
                timestamp: fallback_timestamp.clone(),
                computer: computer_name.to_string(),
                artifact: "linux:cron:user_spool".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: user.clone(),
                target_username: user.clone(),
                processname: proc_name,
                commandline: Some(format!("User Cron: {}", command)),
                parentprocessname: "crond".to_string(),
            });
        }
    }

    Ok(events)
}

/// Parses /etc/anacrontab
pub fn parse_anacrontab_file(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('=') {
            continue;
        }

        // Format: period-in-days delay-in-minutes job-identifier command
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 4 {
            return Err(LinuxPersistenceError::InvalidAnacronEntry(format!(
                "anacrontab:{}: expected 4 fields, got {}",
                line_idx + 1,
                tokens.len()
            )));
        }

        let period = tokens[0];
        let delay = tokens[1];
        let job_id = tokens[2];
        let command = tokens[3..].join(" ");
        let proc_name = tokens.get(3).unwrap_or(&"anacron").to_string();

        events.push(Event {
            timestamp: fallback_timestamp.clone(),
            computer: computer_name.to_string(),
            artifact: "linux:anacron:job".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "root".to_string(),
            target_username: "root".to_string(),
            processname: proc_name,
            commandline: Some(format!("Anacron [{}] (Period: {}d, Delay: {}m): {}", job_id, period, delay, command)),
            parentprocessname: "anacron".to_string(),
        });
    }

    Ok(events)
}

/// Parses periodic cron script directory (/etc/cron.hourly, /etc/cron.daily, etc.)
pub fn parse_cron_periodic_script(file_path: &Path, computer_name: &str) -> Result<Vec<Event>, LinuxPersistenceError> {
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

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("cron_script");
    let parent = file_path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("cron");

    Ok(vec![Event {
        timestamp: fallback_timestamp,
        computer: computer_name.to_string(),
        artifact: format!("linux:cron:periodic:{}", parent),
        event_id: 0,
        pid: 0,
        subject_username: "root".to_string(),
        target_username: "root".to_string(),
        processname: filename.to_string(),
        commandline: Some(format!("Periodic Cron Script: {}", file_path.display())),
        parentprocessname: "run-parts".to_string(),
    }])
}
