pub mod error;
pub mod cron;
pub mod systemd;
pub mod profiles;
pub mod ld_preload;
pub mod ssh;
pub mod sudoers;
pub mod pam;
pub mod udev;
pub mod modules;
pub mod package_manager;
pub mod autostart;
pub mod browser;
pub mod proc;

use crate::event::Event;
use std::path::Path;
use walkdir::WalkDir;

/// Checks whether a given directory is a Linux filesystem or triage collection
pub fn is_linux_target(target: &Path) -> bool {
    if !target.is_dir() {
        return false;
    }

    let target_str = target.to_string_lossy().to_lowercase();
    if target_str.contains("uac") || target_str.contains("linux") {
        return true;
    }

    for entry in WalkDir::new(target).max_depth(4).into_iter().flatten() {
        let p = entry.path();
        let fname = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

        if fname == "live_response"
            || fname == "[root]"
            || fname == "passwd"
            || fname == "shadow"
            || fname == "crontab"
            || fname == "anacrontab"
            || fname == "ld.so.preload"
            || fname == "sshd_config"
            || fname.ends_with(".service")
            || fname.ends_with(".timer")
        {
            return true;
        }

        if entry.file_type().is_dir()
            && (p.join("live_response").exists()
                || p.join("[root]").exists()
                || (p.join("etc").exists() && p.join("var").join("log").exists())
                || p.join("var").join("log").exists()
                || p.join("audit.log").exists()
                || p.join("systemd").exists()
                || p.join("cron.d").exists()
                || p.join("etc").join("shadow").exists()
                || p.join("etc").join("passwd").exists())
        {
            return true;
        }
    }

    false
}

thread_local! {
    /// Root of the Linux evidence being processed, so parsers can print
    /// paths as they were on the host instead of where they were staged.
    static EVIDENCE_ROOT: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}

const TOP_LEVEL_DIRS: &[&str] = &[
    "etc", "var", "home", "root", "usr", "lib", "lib64", "bin", "sbin", "opt", "run", "srv", "boot", "proc", "tmp", "dev",
];

/// The path of a collected file as it was on the host: `/etc/cron.daily/apport`.
///
/// Strips the evidence root set by [`process_linux_target`], then a UAC
/// `[root]` marker, and as a last resort everything before the last
/// well-known top-level directory. Always forward slashes.
pub fn evidence_path(path: &Path) -> String {
    let root = EVIDENCE_ROOT.with(|r| r.borrow().clone());
    let rel = root.as_deref().and_then(|r| path.strip_prefix(r).ok()).unwrap_or(path);
    let comps: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    let mut start = 0usize;
    if let Some(i) = comps.iter().rposition(|c| c == "[root]") {
        start = i + 1;
    } else if root.is_none() {
        if let Some(i) = comps.iter().rposition(|c| TOP_LEVEL_DIRS.contains(&c.as_str())) {
            start = i;
            if i > 0 && matches!(comps[i].as_str(), "lib" | "lib64" | "bin" | "sbin" | "share" | "local") && comps[i - 1] == "usr" {
                start = i - 1;
            }
        }
    }
    format!("/{}", comps[start..].join("/"))
}

/// Key under which two findings count as the same thing. `/usr/lib`, `/usr/bin`
/// and `/usr/sbin` fold onto `/lib`, `/bin`, `/sbin`: on a usr-merged system
/// they are one directory, and collectors copy both.
fn dedupe_key(e: &Event) -> String {
    let norm = |s: &str| s.replace("/usr/lib/", "/lib/").replace("/usr/bin/", "/bin/").replace("/usr/sbin/", "/sbin/");
    // the timestamp is left out: a copy with a different mtime is still the same finding
    format!(
        "{}|{}|{}|{}|{}",
        e.artifact,
        e.subject_username,
        norm(&e.processname),
        norm(e.commandline.as_deref().unwrap_or("")),
        norm(&e.parentprocessname)
    )
}

/// Drop findings identical to one already kept; each drop is an INFO diagnostic.
pub fn dedupe_events(events: Vec<Event>) -> Vec<Event> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(events.len());
    for e in events {
        if seen.insert(dedupe_key(&e)) {
            out.push(e);
        } else {
            crate::windows::diag::record(crate::errors::FaramirError::LinuxDuplicateSkipped(format!(
                "{} {}",
                e.artifact,
                e.commandline.as_deref().unwrap_or(&e.processname)
            )));
        }
    }
    out
}

/// Events for what the ext4 journal gave back (`<volume>.recovered`, see
/// `ingest::ext_journal`): each recovered file goes through the same parsers
/// as a live one, its artifact gets a `linux:deleted:` or
/// `linux:previous_version:` prefix and its command line carries the
/// deletion time and the journal transaction. A deleted file whose content
/// is gone still yields one `linux:deleted:file` row with its name.
pub fn process_recovered(dir: &Path, computer_name: &str) -> Vec<Event> {
    use crate::ingest::ext_journal::read_manifest;
    let Some(entries) = read_manifest(dir) else { return Vec::new() };
    let mut out = Vec::new();
    for e in entries {
        let prefix = if e.kind == "previous_version" { "linux:previous_version:" } else { "linux:deleted:" };
        let note = match (&e.dtime, e.kind.as_str()) {
            (Some(d), "deleted") => format!("[deleted {d}, {}]", e.source),
            (None, "deleted") => format!("[deleted, {}]", e.source),
            _ => format!("[previous version written {}, {}]", e.mtime, e.source),
        };
        let staged = e.staged.as_ref().map(|s| dir.join(s)).filter(|p| p.is_file());
        let mut events = match &staged {
            Some(p) => {
                let root = crate::ingest::ext_journal::staged_root(dir, e.staged.as_deref().unwrap_or(""));
                EVIDENCE_ROOT.with(|r| *r.borrow_mut() = Some(root));
                let mut ev = Vec::new();
                process_single_file(p, computer_name, &mut ev);
                EVIDENCE_ROOT.with(|r| *r.borrow_mut() = None);
                ev
            }
            None => Vec::new(),
        };
        if events.is_empty() {
            // nothing parseable (content reused, or a file the parsers do not read): the name alone is evidence
            events.push(Event {
                timestamp: e.dtime.clone().unwrap_or_else(|| e.mtime.clone()),
                computer: computer_name.to_string(),
                artifact: format!("{prefix}file"),
                event_id: 0,
                pid: 0,
                subject_username: "unknown".into(),
                target_username: "unknown".into(),
                processname: Path::new(&e.path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                commandline: Some(format!(
                    "{} ({} bytes{}) {note}",
                    e.path,
                    e.size,
                    if e.content_recovered { "" } else if e.blocks_reused { ", content blocks reused" } else { ", content not recovered" }
                )),
                parentprocessname: "ext4 journal".into(),
            });
        } else {
            for ev in &mut events {
                ev.artifact = format!("{prefix}{}", ev.artifact.trim_start_matches("linux:"));
                let base = ev.commandline.take().unwrap_or_default();
                ev.commandline = Some(format!("{base} {note} {}", e.path));
                if let Some(d) = &e.dtime {
                    if e.kind == "deleted" {
                        ev.timestamp = d.clone();
                    }
                }
            }
        }
        out.extend(events);
    }
    dedupe_events(out)
}

/// Recursively scans and extracts Linux persistence events from target directory or file
pub fn process_linux_target(target: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let root = if target.is_file() { target.parent().map(Path::to_path_buf) } else { Some(target.to_path_buf()) };
    EVIDENCE_ROOT.with(|r| *r.borrow_mut() = root);

    if target.is_file() {
        process_single_file(target, computer_name, &mut events);
    } else {
        BROWSER_TREE_PASS.with(|b| b.set(true));
        for entry in WalkDir::new(target).into_iter().flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            process_single_file(path, computer_name, &mut events);
        }
        BROWSER_TREE_PASS.with(|b| b.set(false));
        events.extend(browser::events_for_tree(target, computer_name));
    }

    EVIDENCE_ROOT.with(|r| *r.borrow_mut() = None);
    dedupe_events(events)
}

thread_local! {
    /// Set while a directory walk is in progress: browser files are then
    /// handled by one tree pass instead of one call per file.
    static BROWSER_TREE_PASS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn process_single_file(path: &Path, computer_name: &str, events: &mut Vec<Event>) {
    let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let path_str = path.to_string_lossy().to_string();

    // 1. Systemd units
    if fname.ends_with(".service") {
        if let Ok(ev) = systemd::parse_systemd_service(path, computer_name) {
            events.extend(ev);
        }
    } else if fname.ends_with(".timer") {
        if let Ok(ev) = systemd::parse_systemd_timer(path, computer_name) {
            events.extend(ev);
        }
    } else if fname.ends_with(".socket") || fname.ends_with(".path") {
        if let Ok(ev) = systemd::parse_systemd_socket_or_path(path, computer_name) {
            events.extend(ev);
        }
    } else if path_str.contains("system-generators") {
        if let Ok(ev) = systemd::parse_systemd_generator(path, computer_name) {
            events.extend(ev);
        }
    }

    // 2. Cron
    else if fname == "crontab" || path_str.contains("/cron.d/") || path_str.contains("\\cron.d\\") {
        if let Ok(ev) = cron::parse_cron_system_file(path, computer_name) {
            events.extend(ev);
        }
    } else if path_str.contains("spool/cron") || path_str.contains("spool\\cron") {
        if let Ok(ev) = cron::parse_cron_spool_file(path, computer_name) {
            events.extend(ev);
        }
    } else if fname == "anacrontab" {
        if let Ok(ev) = cron::parse_anacrontab_file(path, computer_name) {
            events.extend(ev);
        }
    } else if path_str.contains("cron.hourly") || path_str.contains("cron.daily")
        || path_str.contains("cron.weekly") || path_str.contains("cron.monthly")
    {
        if let Ok(ev) = cron::parse_cron_periodic_script(path, computer_name) {
            events.extend(ev);
        }
    }

    // 3. Shell profiles & rc.local
    else if fname == "rc.local" || fname.ends_with(".bashrc") || fname.ends_with(".profile")
        || fname == "profile" || fname == "bash.bashrc" || fname.ends_with(".zshrc")
        || fname.ends_with(".zprofile") || fname == "environment" || path_str.contains("/profile.d/")
        || path_str.contains("\\profile.d\\")
    {
        if let Ok(ev) = profiles::parse_shell_script(path, computer_name) {
            events.extend(ev);
        }
    }

    // 4. Dynamic Linker Preload
    else if fname == "ld.so.preload" {
        if let Ok(ev) = ld_preload::parse_ld_so_preload(path, computer_name) {
            events.extend(ev);
        }
    }

    // 5. SSH
    else if fname == "authorized_keys" || fname == "authorized_keys2" {
        if let Ok(ev) = ssh::parse_ssh_authorized_keys(path, computer_name) {
            events.extend(ev);
        }
    } else if fname == "sshd_config" {
        if let Ok(ev) = ssh::parse_sshd_config(path, computer_name) {
            events.extend(ev);
        }
    }

    // 6. Sudoers
    else if fname == "sudoers" || path_str.contains("/sudoers.d/") || path_str.contains("\\sudoers.d\\") {
        if let Ok(ev) = sudoers::parse_sudoers_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 7. PAM
    else if path_str.contains("/pam.d/") || path_str.contains("\\pam.d\\") {
        if let Ok(ev) = pam::parse_pam_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 8. Udev
    else if fname.ends_with(".rules") && (path_str.contains("udev") || path_str.contains("rules.d")) {
        if let Ok(ev) = udev::parse_udev_rule_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 9. Kernel modules
    else if fname == "modules" || path_str.contains("modules-load.d") || path_str.contains("modprobe.d") {
        if let Ok(ev) = modules::parse_kernel_modules_config(path, computer_name) {
            events.extend(ev);
        }
    }

    // 10. Package manager hooks
    else if path_str.contains("apt.conf.d") {
        if let Ok(ev) = package_manager::parse_apt_hook_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 11. XDG Autostart
    else if fname.ends_with(".desktop") && (path_str.contains("autostart") || path_str.contains("xdg")) {
        if let Ok(ev) = autostart::parse_xdg_desktop_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 11b. Browser extensions (Chromium profiles, Firefox, policy files). A
    //      directory walk handles them once per tree (see process_linux_target),
    //      so a manifest can be folded into its Preferences entry.
    else if browser::is_browser_file(path) && !BROWSER_TREE_PASS.with(|b| b.get()) {
        events.extend(browser::parse_browser_file(path, computer_name));
    }

    // 12. Running processes & deleted binaries
    else if fname == "running_processes_full_paths.txt" || fname == "ps.txt" {
        if let Ok(ev) = proc::parse_running_processes_file(path, computer_name) {
            events.extend(ev);
        }
    }
}
