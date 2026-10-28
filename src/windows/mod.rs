//! Windows persistence engine: hive handling and every registry/filesystem technique.

pub mod diag;
pub mod hives;
pub mod techniques;
pub mod txlog;

pub use hives::{classify_hive, discover_hives, open_hive, HiveInfo, HiveKind, RecoveryReport};
pub use techniques::{run_all, run_technique, HiveSet, KeyRoot, Persistence, Root, TechniqueId};

use crate::event::Event;

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".scr", ".com", ".msi", ".ocx",
    ".sys", ".cpl", ".hta", ".pif", ".lnk", ".py", ".sh",
];

/// Process (file) name of a command line: the image path up to its extension,
/// with quotes, folders and arguments stripped. Switches like `/thfirstsetup`
/// and unquoted paths with spaces (`%ProgramFiles%\Windows Mail\wab.exe`) are handled.
pub fn process_name_of(command: &str) -> String {
    let v = command.trim();
    if v.is_empty() {
        return String::new();
    }
    let lower = v.to_lowercase();
    let mut best: Option<usize> = None;
    for ext in EXECUTABLE_EXTENSIONS {
        if let Some(pos) = lower.find(ext) {
            let end = pos + ext.len();
            // the extension must end the token: followed by nothing, space, quote or comma
            let boundary = lower[end..].chars().next().map(|c| c.is_whitespace() || c == '"' || c == ',' || c == '\'').unwrap_or(true);
            if boundary && best.is_none_or(|b| end < b) {
                best = Some(end);
            }
        }
    }
    let head = match best {
        Some(end) => &v[..end],
        None => v.split_whitespace().next().unwrap_or(v),
    };
    head.trim_matches(|c| c == '"' || c == '\'')
        .rsplit('\\')
        .next()
        .unwrap_or(head)
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string()
}

/// Convert a persistence finding into the unified Caarea/Masstin timeline event.
pub fn persistence_to_event(p: &Persistence, computer_name: &str) -> Event {
    let processname = process_name_of(&p.value);

    let clean_tech = p
        .technique
        .to_lowercase()
        .replace([' ', '(', ')', '/', '.'], "_");
    let artifact = format!("windows:persistence:{}", clean_tech);

    Event {
        timestamp: p.timestamp.clone(),
        computer: computer_name.to_string(),
        artifact,
        event_id: 0,
        pid: 0,
        subject_username: p.access_gained.clone(),
        target_username: p.access_gained.clone(),
        processname,
        commandline: Some(p.value.clone()),
        parentprocessname: p.path.clone(),
    }
}
