//! Browser extensions as persistence (MITRE T1176), shared by the Windows
//! and Linux engines: Chromium-family profiles (`Preferences`, `Secure
//! Preferences`, `Extensions/<id>/<version>/manifest.json`), Firefox
//! profiles (`extensions.json`), and enterprise policy files
//! (`policies.json`, managed policy JSON, `external_extensions.json`).
//!
//! Every parser is bounded and tolerant: a malformed file is reported as a
//! diagnostic and skipped, never a panic.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;
use walkdir::WalkDir;

use crate::errors::FaramirError;
use crate::windows::diag;

/// Permissions worth calling out on a row.
pub const DANGEROUS_PERMISSIONS: &[&str] = &[
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "webRequest", "webRequestBlocking", "declarativeNetRequest", "cookies", "nativeMessaging",
    "debugger", "proxy", "history", "tabs", "scripting", "clipboardRead", "downloads", "management", "privacy", "webNavigation", "identity",
    "contentSettings", "browsingData", "desktopCapture", "tabCapture", "pageCapture",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRecord {
    pub browser: String,
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    /// `web store`, `force-installed by policy`, `unpacked (developer mode)`, `sideloaded`, `external registry`, `manifest only`…
    pub origin: String,
    pub update_url: String,
    pub install_time: Option<String>,
    pub permissions: Vec<String>,
    pub enabled: bool,
    /// File the record came from.
    pub file: String,
}

impl ExtensionRecord {
    /// One-line description for the `value` column.
    pub fn summary(&self) -> String {
        let mut s = format!("{} {}", self.browser, self.id);
        if !self.name.is_empty() {
            s.push_str(&format!(" \"{}\"", self.name));
        }
        if !self.version.is_empty() {
            s.push_str(&format!(" v{}", self.version));
        }
        s.push_str(&format!(" [{}]", self.origin));
        if !self.enabled {
            s.push_str(" [disabled]");
        }
        if !self.update_url.is_empty() && !is_official_store_url(&self.update_url) {
            s.push_str(&format!(" update_url={}", self.update_url));
        }
        let risky: Vec<&str> = self.permissions.iter().map(String::as_str).filter(|p| DANGEROUS_PERMISSIONS.iter().any(|d| d.eq_ignore_ascii_case(p))).collect();
        if !risky.is_empty() {
            s.push_str(&format!(" permissions={}", risky.join(",")));
        }
        s
    }

    /// Worth a row at all: everything the user did not get from the store, or
    /// that reaches everything the browser sees.
    pub fn is_noteworthy(&self) -> bool {
        true
    }
}

pub fn is_official_store_url(url: &str) -> bool {
    let u = url.to_lowercase();
    u.contains("clients2.google.com/service/update2/crx")
        || u.contains("edge.microsoft.com/extensionwebstorebase/v1/crx")
        || u.contains("addons.mozilla.org")
        || u.contains("extensionupdater.brave.com")
}

/// Browser a policy key / managed path belongs to.
pub fn browser_of_policy_path(path: &str) -> &'static str {
    let p = path.to_lowercase();
    if p.contains("edge") {
        "Edge"
    } else if p.contains("brave") {
        "Brave"
    } else if p.contains("chromium") {
        "Chromium"
    } else if p.contains("mozilla") || p.contains("firefox") {
        "Firefox"
    } else if p.contains("chrome") || p.contains("google") {
        "Chrome"
    } else if p.contains("vivaldi") {
        "Vivaldi"
    } else if p.contains("opera") {
        "Opera"
    } else {
        "Browser"
    }
}

/// Chromium `install_time`: microseconds since 1601-01-01, as a decimal string.
pub fn webkit_time_to_string(s: &str) -> Option<String> {
    let micros: i64 = s.trim().parse().ok()?;
    if micros <= 0 {
        return None;
    }
    let unix_secs = micros / 1_000_000 - 11_644_473_600;
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, ((micros % 1_000_000) * 1000) as u32).map(|d| d.format(crate::windows::techniques::FORMAT_DATE).to_string())
}

fn millis_to_string(ms: i64) -> Option<String> {
    if ms <= 0 {
        return None;
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32).map(|d| d.format(crate::windows::techniques::FORMAT_DATE).to_string())
}

/// Chromium extension location codes (`extensions/common/manifest.h`).
pub fn chromium_location_label(code: i64, from_webstore: bool) -> (&'static str, bool) {
    // (label, is a component the browser ships with)
    match code {
        1 => (if from_webstore { "web store" } else { "user install, not from the store" }, false),
        2 => ("external preferences file", false),
        3 => ("external registry install", false),
        4 => ("unpacked (developer mode)", false),
        5 => ("browser component", true),
        6 => ("external preferences download", false),
        7 => ("force-installed by policy (download)", false),
        8 => ("loaded from the command line", false),
        9 => ("force-installed by policy", false),
        10 => ("external browser component", true),
        _ => ("unknown location", false),
    }
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default()
}

/// `extensions.settings` of a Chromium `Preferences` / `Secure Preferences`.
pub fn parse_chromium_preferences(text: &str, browser: &str, profile: &str, file: &str) -> Result<Vec<ExtensionRecord>, FaramirError> {
    let v: Value = serde_json::from_str(text).map_err(|e| FaramirError::BrowserProfileParseError(format!("{file}: {e}")))?;
    let Some(settings) = v.pointer("/extensions/settings").and_then(Value::as_object) else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for (id, e) in settings {
        if !id.chars().all(|c| c.is_ascii_lowercase()) || id.len() != 32 {
            continue;
        }
        let location = e.get("location").and_then(Value::as_i64).unwrap_or(0);
        let from_store = e.get("from_webstore").and_then(Value::as_bool).unwrap_or(false);
        let (label, component) = chromium_location_label(location, from_store);
        if component {
            continue;
        }
        let manifest = e.get("manifest");
        let name = manifest.and_then(|m| m.get("name")).and_then(Value::as_str).unwrap_or("").to_string();
        let version = manifest.and_then(|m| m.get("version")).and_then(Value::as_str).unwrap_or("").to_string();
        let update_url = manifest.and_then(|m| m.get("update_url")).and_then(Value::as_str).unwrap_or("").to_string();
        let mut permissions = str_list(manifest.and_then(|m| m.get("permissions")));
        permissions.extend(str_list(manifest.and_then(|m| m.get("host_permissions"))));
        permissions.extend(str_list(e.pointer("/granted_permissions/api")));
        permissions.extend(str_list(e.pointer("/granted_permissions/explicit_host")));
        permissions.sort();
        permissions.dedup();
        let path = e.get("path").and_then(Value::as_str).unwrap_or("");
        let mut origin = label.to_string();
        if path.contains(':') || path.starts_with('/') || path.starts_with('\\') {
            origin.push_str(&format!(", path {path}"));
        }
        let state = e.get("state").and_then(Value::as_i64).unwrap_or(1);
        out.push(ExtensionRecord {
            browser: browser.to_string(),
            profile: profile.to_string(),
            id: id.clone(),
            name,
            version,
            origin,
            update_url,
            install_time: e.get("install_time").and_then(Value::as_str).and_then(webkit_time_to_string),
            permissions,
            enabled: state != 0,
            file: file.to_string(),
        });
    }
    Ok(out)
}

/// `Extensions/<id>/<version>/manifest.json`.
pub fn parse_chromium_manifest(text: &str, browser: &str, profile: &str, id: &str, file: &str) -> Result<ExtensionRecord, FaramirError> {
    let m: Value = serde_json::from_str(text).map_err(|e| FaramirError::BrowserProfileParseError(format!("{file}: {e}")))?;
    let mut permissions = str_list(m.get("permissions"));
    permissions.extend(str_list(m.get("host_permissions")));
    Ok(ExtensionRecord {
        browser: browser.to_string(),
        profile: profile.to_string(),
        id: id.to_string(),
        name: m.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
        version: m.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
        origin: "manifest on disk (not listed in Preferences)".to_string(),
        update_url: m.get("update_url").and_then(Value::as_str).unwrap_or("").to_string(),
        install_time: None,
        permissions,
        enabled: true,
        file: file.to_string(),
    })
}

/// Firefox `extensions.json`.
pub fn parse_firefox_extensions(text: &str, profile: &str, file: &str) -> Result<Vec<ExtensionRecord>, FaramirError> {
    let v: Value = serde_json::from_str(text).map_err(|e| FaramirError::BrowserProfileParseError(format!("{file}: {e}")))?;
    let Some(addons) = v.get("addons").and_then(Value::as_array) else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for a in addons {
        let kind = a.get("type").and_then(Value::as_str).unwrap_or("");
        if kind != "extension" {
            continue;
        }
        let location = a.get("location").and_then(Value::as_str).unwrap_or("");
        if matches!(location, "app-builtin" | "app-system-defaults" | "app-system-addons" | "app-builtin-addons") {
            continue;
        }
        let source = a.get("sourceURI").and_then(Value::as_str).unwrap_or("").to_string();
        let origin = match location {
            "app-profile" => {
                if source.contains("addons.mozilla.org") {
                    "Mozilla add-ons".to_string()
                } else if source.is_empty() {
                    "profile install, source unknown".to_string()
                } else {
                    "profile install from outside Mozilla add-ons".to_string()
                }
            }
            "app-system-share" | "app-global" | "app-system-local" | "app-system-user" => format!("sideloaded ({location})"),
            "winreg-app-global" | "winreg-app-user" => format!("installed through the registry ({location})"),
            "app-system-profile" | "app-system-policy" => format!("installed by policy ({location})"),
            other => format!("location {other}"),
        };
        let mut permissions = str_list(a.pointer("/userPermissions/permissions"));
        permissions.extend(str_list(a.pointer("/userPermissions/origins")));
        out.push(ExtensionRecord {
            browser: "Firefox".to_string(),
            profile: profile.to_string(),
            id: a.get("id").and_then(Value::as_str).unwrap_or("").to_string(),
            name: a.pointer("/defaultLocale/name").and_then(Value::as_str).unwrap_or("").to_string(),
            version: a.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
            origin,
            update_url: source,
            install_time: a.get("installDate").and_then(Value::as_i64).and_then(millis_to_string),
            permissions,
            enabled: !a.get("userDisabled").and_then(Value::as_bool).unwrap_or(false) && a.get("active").and_then(Value::as_bool).unwrap_or(true),
            file: file.to_string(),
        });
    }
    Ok(out)
}

/// `ExtensionSettings` as JSON (policy registry blob or managed policy file).
pub fn parse_extension_settings_json(text: &str, browser: &str) -> Vec<ExtensionRecord> {
    let Ok(v) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let Some(obj) = v.as_object() else { return Vec::new() };
    obj.iter()
        .filter(|(id, _)| id.as_str() != "*")
        .filter_map(|(id, s)| {
            let mode = s.get("installation_mode").and_then(Value::as_str).unwrap_or("");
            if matches!(mode, "blocked" | "removed" | "allowed" | "") {
                return None;
            }
            Some(ExtensionRecord {
                browser: browser.to_string(),
                profile: "policy".to_string(),
                id: id.clone(),
                name: String::new(),
                version: String::new(),
                origin: format!("{mode} by policy"),
                update_url: s.get("update_url").or_else(|| s.get("install_url")).and_then(Value::as_str).unwrap_or("").to_string(),
                install_time: None,
                permissions: Vec::new(),
                enabled: true,
                file: String::new(),
            })
        })
        .collect()
}

/// Enterprise policy files: Firefox `policies.json` (`policies.Extensions.Install`,
/// `policies.ExtensionSettings`), Chromium managed JSON (`ExtensionInstallForcelist`,
/// `ExtensionSettings`), Chromium `external_extensions.json` (`{id: {external_update_url|external_crx}}`).
pub fn parse_policy_file(text: &str, browser: &str, file: &str) -> Result<Vec<ExtensionRecord>, FaramirError> {
    let v: Value = serde_json::from_str(text).map_err(|e| FaramirError::BrowserProfileParseError(format!("{file}: {e}")))?;
    let mut out = Vec::new();
    let root = v.get("policies").unwrap_or(&v);
    let mk = |id: String, origin: String, url: String| ExtensionRecord {
        browser: browser.to_string(),
        profile: "policy".to_string(),
        id,
        name: String::new(),
        version: String::new(),
        origin,
        update_url: url,
        install_time: None,
        permissions: Vec::new(),
        enabled: true,
        file: file.to_string(),
    };
    for u in str_list(root.pointer("/Extensions/Install")) {
        let id = u.rsplit('/').next().unwrap_or(&u).to_string();
        out.push(mk(id, "force-installed by policy".into(), u.clone()));
    }
    for u in str_list(root.get("ExtensionInstallForcelist")) {
        let (id, url) = u.split_once(';').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((u.clone(), String::new()));
        out.push(mk(id, "force-installed by policy".into(), url));
    }
    if let Some(settings) = root.get("ExtensionSettings") {
        let text = settings.to_string();
        for mut e in parse_extension_settings_json(&text, browser) {
            e.file = file.to_string();
            out.push(e);
        }
    }
    if root.get("policies").is_none() && root.get("ExtensionInstallForcelist").is_none() && root.get("ExtensionSettings").is_none() && root.get("Extensions").is_none() {
        if let Some(obj) = v.as_object() {
            for (id, e) in obj {
                let url = e.get("external_update_url").and_then(Value::as_str).unwrap_or("").to_string();
                let crx = e.get("external_crx").and_then(Value::as_str).unwrap_or("").to_string();
                if url.is_empty() && crx.is_empty() {
                    continue;
                }
                out.push(mk(id.clone(), format!("external_extensions.json{}", if crx.is_empty() { String::new() } else { format!(" crx {crx}") }), url));
            }
        }
    }
    Ok(out)
}

// ─── what to copy out of a browser profile ───────────────────────────────────

/// Profile directories under a user's home (Linux) worth looking at.
pub const LINUX_BROWSER_HOME_DIRS: &[&str] = &[
    ".config/google-chrome",
    ".config/chromium",
    ".config/microsoft-edge",
    ".config/BraveSoftware/Brave-Browser",
    ".config/vivaldi",
    ".config/opera",
    ".mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
    "snap/chromium/common/chromium",
    ".var/app/org.mozilla.firefox/.mozilla/firefox",
    ".var/app/com.google.Chrome/config/google-chrome",
];

/// System-wide policy and external-extension directories (Linux).
pub const LINUX_BROWSER_POLICY_DIRS: &[&str] = &[
    "/etc/opt/chrome/policies/managed",
    "/etc/chromium/policies/managed",
    "/etc/opt/edge/policies/managed",
    "/etc/brave/policies/managed",
    "/etc/firefox/policies",
    "/usr/lib/firefox/distribution",
    "/usr/lib64/firefox/distribution",
    "/usr/lib/firefox-esr/distribution",
    "/usr/share/google-chrome/extensions",
    "/usr/share/chromium/extensions",
    "/opt/google/chrome/extensions",
];

/// Profile directories under a Windows user profile, relative to the user folder.
pub const WINDOWS_BROWSER_USER_DIRS: &[&[&str]] = &[
    &["AppData", "Local", "Google", "Chrome", "User Data"],
    &["AppData", "Local", "Microsoft", "Edge", "User Data"],
    &["AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"],
    &["AppData", "Local", "Chromium", "User Data"],
    &["AppData", "Local", "Vivaldi", "User Data"],
    &["AppData", "Roaming", "Opera Software", "Opera Stable"],
    &["AppData", "Roaming", "Mozilla", "Firefox", "Profiles"],
];

/// Only these files are copied out of a browser profile tree.
pub fn is_profile_file_wanted(name: &str, parent_chain_has_extensions: bool) -> bool {
    match name {
        "Preferences" | "Secure Preferences" | "extensions.json" | "policies.json" | "external_extensions.json" => true,
        "manifest.json" => parent_chain_has_extensions,
        _ => false,
    }
}

/// Profile subdirectories that hold caches and storage, never extension data.
pub fn is_profile_dir_skipped(name: &str) -> bool {
    let n = name.to_lowercase();
    matches!(
        n.as_str(),
        "cache" | "code cache" | "gpucache" | "service worker" | "indexeddb" | "local storage" | "session storage" | "blob_storage" | "storage" | "cache2"
            | "startupcache" | "file system" | "sessions" | "dawncache" | "grshadercache" | "shadercache" | "safe browsing" | "local extension settings"
            | "sync extension settings" | "extension rules" | "extension state" | "extension scripts" | "webstorage" | "shared_proto_db" | "databases"
            | "videodecodestats" | "download service" | "platform notifications" | "network" | "site characteristics database" | "crashpad" | "crashes"
            | "component_crx_cache" | "browsermetrics" | "thumbnails" | "sessionstore-backups" | "storage-sync-v2" | "minidumps" | "saved telemetry pings"
            | "datareporting" | "bookmarkbackups" | "security_state" | "optimization_guide_hint_cache_store" | "optimization_guide_model_store"
            | "autofillstrikedatabase" | "feature_engagement_tracker" | "segmentation_platform" | "webrtc logs" | "webrtcidentitystore" | "worker"
    ) || n.starts_with("optimization_guide")
}

// ─── finding the files in an evidence tree ───────────────────────────────────

const CHROMIUM_DIRS: &[(&str, &str)] = &[
    ("google\\chrome", "Chrome"),
    ("google/chrome", "Chrome"),
    ("google-chrome", "Chrome"),
    ("microsoft\\edge", "Edge"),
    ("microsoft/edge", "Edge"),
    ("microsoft-edge", "Edge"),
    ("bravesoftware", "Brave"),
    ("chromium", "Chromium"),
    ("vivaldi", "Vivaldi"),
    ("opera", "Opera"),
];

fn chromium_browser_of(path_lower: &str) -> Option<&'static str> {
    CHROMIUM_DIRS.iter().find(|(d, _)| path_lower.contains(d)).map(|(_, b)| *b)
}

/// `Default`, `Profile 1`… : the directory holding the file (Preferences) or
/// the one above `Extensions`.
fn profile_of(path: &Path, levels_up: usize) -> String {
    let mut p = path;
    for _ in 0..levels_up {
        p = p.parent().unwrap_or(p);
    }
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

/// Walk an evidence tree and collect every extension record it holds.
pub fn scan_tree(source: &Path) -> Vec<ExtensionRecord> {
    let mut out: Vec<ExtensionRecord> = Vec::new();
    let mut manifests: Vec<ExtensionRecord> = Vec::new();
    for entry in WalkDir::new(source).into_iter().flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
        let lower = p.to_string_lossy().to_lowercase().replace('\\', "/");
        let file = p.to_string_lossy().to_string();
        let read = |p: &Path| std::fs::read_to_string(p).ok();
        match name.as_str() {
            "Preferences" | "Secure Preferences" => {
                let Some(browser) = chromium_browser_of(&lower) else { continue };
                let Some(text) = read(p) else { continue };
                match parse_chromium_preferences(&text, browser, &profile_of(p, 1), &file) {
                    Ok(v) => out.extend(v),
                    Err(e) => {
                        diag::record(e);
                    }
                }
            }
            "extensions.json" => {
                if !(lower.contains("firefox") || lower.contains(".mozilla") || lower.contains("profiles/")) {
                    continue;
                }
                let Some(text) = read(p) else { continue };
                match parse_firefox_extensions(&text, &profile_of(p, 1), &file) {
                    Ok(v) => out.extend(v),
                    Err(e) => {
                        diag::record(e);
                    }
                }
            }
            "manifest.json" => {
                // Extensions/<id>/<version>/manifest.json
                let id = profile_of(p, 2);
                let grand = p.ancestors().nth(3).and_then(|a| a.file_name()).map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                if grand != "extensions" || id.len() != 32 {
                    continue;
                }
                let Some(browser) = chromium_browser_of(&lower) else { continue };
                let Some(text) = read(p) else { continue };
                match parse_chromium_manifest(&text, browser, &profile_of(p, 4), &id, &file) {
                    Ok(r) => manifests.push(r),
                    Err(e) => {
                        diag::record(e);
                    }
                }
            }
            "policies.json" | "external_extensions.json" => {
                let browser = if name == "policies.json" && !lower.contains("chrome") && !lower.contains("chromium") && !lower.contains("edge") && !lower.contains("brave") { "Firefox" } else { browser_of_policy_path(&lower) };
                let Some(text) = read(p) else { continue };
                match parse_policy_file(&text, browser, &file) {
                    Ok(v) => out.extend(v),
                    Err(e) => {
                        diag::record(e);
                    }
                }
            }
            _ => {
                // Chromium managed policy directories hold arbitrary *.json
                if name.ends_with(".json") && lower.contains("/policies/managed/") {
                    let Some(text) = read(p) else { continue };
                    if let Ok(v) = parse_policy_file(&text, browser_of_policy_path(&lower), &file) {
                        out.extend(v);
                    }
                }
            }
        }
    }
    // a manifest only adds what no Preferences file already listed for that profile
    let seen: HashSet<(String, String, String)> = out.iter().map(|e| (e.browser.clone(), e.profile.clone(), e.id.clone())).collect();
    for m in manifests {
        if !seen.contains(&(m.browser.clone(), m.profile.clone(), m.id.clone())) {
            out.push(m);
        }
    }
    out
}
