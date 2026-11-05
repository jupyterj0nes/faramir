//! Windows persistence engine: hive handling and every registry/filesystem technique.

/// `println!` that honours `--silent` (see [`diag::set_quiet`]).
macro_rules! out {
    ($($t:tt)*) => {
        if !$crate::windows::diag::is_quiet() {
            println!($($t)*);
        }
    };
}

pub mod deleted;
pub mod diag;
pub mod extra;
pub mod hives;
pub mod techniques;
pub mod txlog;
pub mod vss;

pub use hives::{classify_hive, discover_hives, open_hive, HiveInfo, HiveKind, RecoveryReport};
pub use techniques::{run_all, run_technique, HiveSet, KeyRoot, Persistence, Root, TechniqueId};
pub use vss::fold_vss_findings;

use crate::event::Event;
use std::path::Path;

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

/// Convert a persistence finding into a timeline event. Paths in
/// `source_file` are left as the engine stamped them; see
/// [`persistence_to_event_in`] to make them relative to the evidence root.
pub fn persistence_to_event(p: &Persistence, computer_name: &str) -> Event {
    persistence_to_event_in(p, computer_name, None)
}

/// The `source_file` column of a finding: the file it was read from (the
/// hive, the task XML, the profile, the carved hive), made relative to the
/// evidence root when one is given, then `:` and the key inside it. A
/// finding whose path is the file itself (a startup-folder entry, a script)
/// gives the file alone; a finding stamped with no origin gives its path.
pub fn source_file_of(p: &Persistence, root: Option<&Path>) -> String {
    if p.origin.is_empty() {
        return p.path.clone();
    }
    let origin = relative_to(&p.origin, root);
    // the path may quote the file itself (a VSS or carved finding says which
    // copy it came from): the machine's extraction folder has no place there
    let path = match root {
        Some(r) => {
            let prefix = format!("{}{}", r.display(), std::path::MAIN_SEPARATOR);
            p.path.replace(&prefix, "")
        }
        None => p.path.clone(),
    };
    if path.is_empty() || path == origin {
        origin
    } else if path.contains(&origin) {
        path
    } else {
        format!("{origin}:{path}")
    }
}

/// `path` relative to `root` when it lies under it, as text; unchanged otherwise.
fn relative_to(path: &str, root: Option<&Path>) -> String {
    match root.and_then(|r| Path::new(path).strip_prefix(r).ok()) {
        Some(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().to_string(),
        _ => path.to_string(),
    }
}

/// Convert a persistence finding into the timeline event, with the file in
/// `source_file` relative to `root` (the evidence directory or the folder an
/// image was extracted to), so the column reads the same on every machine.
pub fn persistence_to_event_in(p: &Persistence, computer_name: &str, root: Option<&Path>) -> Event {
    let processname = process_name_of(&p.value);

    let clean_tech = p
        .technique
        .to_lowercase()
        .replace([' ', '(', ')', '/', '.'], "_");
    let artifact = if p.source.starts_with(crate::carve::SOURCE_CARVED_DELETED) {
        format!("windows:persistence:carved:deleted:{}", clean_tech)
    } else if p.source.starts_with(crate::carve::SOURCE_CARVED) {
        format!("windows:persistence:carved:{}", clean_tech)
    } else if p.source.starts_with("vss:") {
        format!("windows:persistence:removed_since_vss:{}", clean_tech)
    } else if p.source == deleted::SOURCE_DELETED {
        format!("windows:persistence:deleted:{}", clean_tech)
    } else {
        format!("windows:persistence:{}", clean_tech)
    };

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
        source_file: source_file_of(p, root),
    }
}
