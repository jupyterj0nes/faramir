//! Browser extensions on Linux: Chromium-family profiles under
//! `~/.config/<browser>/<profile>/`, Firefox `~/.mozilla/firefox/<profile>/
//! extensions.json`, and the enterprise policy directories.

use std::path::Path;

use crate::browser_ext::{self, ExtensionRecord};
use crate::event::Event;

/// Does this file hold extension data worth parsing?
pub fn is_browser_file(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let lower = path.to_string_lossy().to_lowercase().replace('\\', "/");
    match name.as_str() {
        "Preferences" | "Secure Preferences" => lower.contains("/.config/") || lower.contains("/snap/") || lower.contains("/.var/app/"),
        "extensions.json" => lower.contains(".mozilla") || lower.contains("firefox"),
        "manifest.json" => lower.contains("/extensions/") && (lower.contains("/.config/") || lower.contains("/snap/") || lower.contains("/.var/app/")),
        "policies.json" | "external_extensions.json" => true,
        _ => name.ends_with(".json") && lower.contains("/policies/managed/"),
    }
}

fn to_event(e: &ExtensionRecord, computer_name: &str) -> Event {
    let forced = e.origin.contains("policy");
    let user = e.file.split(['/', '\\']).skip_while(|c| *c != "home").nth(1).unwrap_or(if e.file.contains("/root/") { "root" } else { "system" }).to_string();
    Event {
        timestamp: e.install_time.clone().unwrap_or_else(|| {
            std::fs::metadata(&e.file)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let d: chrono::DateTime<chrono::Utc> = t.into();
                    d.format(crate::windows::techniques::FORMAT_DATE).to_string()
                })
                .unwrap_or_else(|| "1970-01-01 00:00:00.000".to_string())
        }),
        computer: computer_name.to_string(),
        artifact: if forced { "linux:browser:extension_forced".to_string() } else { "linux:browser:extension".to_string() },
        event_id: 0,
        pid: 0,
        subject_username: user.clone(),
        target_username: user,
        processname: e.browser.to_lowercase(),
        commandline: Some(format!("{} [profile {}] {}", e.summary(), e.profile, super::evidence_path(Path::new(&e.file)))),
        parentprocessname: e.browser.clone(),
    }
}

/// Every extension record under `root`, one pass, manifests folded into
/// their `Preferences` entries.
pub fn events_for_tree(root: &Path, computer_name: &str) -> Vec<Event> {
    browser_ext::scan_tree(root).iter().map(|e| to_event(e, computer_name)).collect()
}

/// Parse one browser file into events.
pub fn parse_browser_file(path: &Path, computer_name: &str) -> Vec<Event> {
    // scan_tree works on a directory; a single file is its own tree
    let parent = path.parent().unwrap_or(path);
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    browser_ext::scan_tree(parent)
        .into_iter()
        .filter(|e| Path::new(&e.file).file_name().map(|n| n.to_string_lossy() == name).unwrap_or(false) && Path::new(&e.file) == path)
        .map(|e| to_event(&e, computer_name))
        .collect()
}
