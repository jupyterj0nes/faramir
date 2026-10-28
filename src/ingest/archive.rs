use chrono::Local;
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::Archive as TarArchive;
use zip::read::ZipArchive;

use crate::ingest::triage::{detect_triage_type, extract_triage_hostname, TriageInfo, TriageType};

/// Known forensic passwords used across DFIR investigations, CTFs, and triage tools
const FORENSIC_PASSWORDS: &[&[u8]] = &[
    b"",
    b"infected",
    b"cyberdefenders.org",
    b"malware",
    b"password",
    b"velox",
    b"Velociraptor",
];

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[FARAMIR {}] {}", timestamp, message);
    }
}

/// Checks if a file path is a supported compressed archive
pub fn is_supported_archive(path: &Path) -> bool {
    let filename = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };

    filename.ends_with(".zip")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".tar")
        || filename.ends_with(".7z")
        || filename.ends_with(".rar")
}

/// Checks if an archive entry is a relevant forensic artifact for execution timelining
pub fn is_relevant_artifact(entry_name: &str) -> bool {
    let lower = entry_name.replace('\\', "/").to_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);

    // Ignore VMware tools driver source modules and installer bundles
    if lower.contains("vmware-tools") || lower.contains("modules/source") {
        return false;
    }

    // EVTX logs
    if file_name.ends_with(".evtx") {
        return true;
    }

    // Windows Registry hives
    let standard_hives = ["system", "software", "sam", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve"];
    if standard_hives.iter().any(|&h| file_name == h || file_name.ends_with(&format!("_{}", h)) || file_name.ends_with(&format!("-{}", h))) {
        return true;
    }
    if file_name.ends_with(".hve") {
        return true;
    }

    // Registry transaction logs: REQUIRED to rebuild dirty hives. Every layout
    // (SYSTEM.LOG1, bob_NTUSER.DAT.LOG1, C_Windows_System32_config_SOFTWARE.LOG2,
    // legacy SYSTEM.LOG) is kept; validation happens later in windows::txlog.
    if file_name.ends_with(".log1") || file_name.ends_with(".log2") {
        return true;
    }
    if let Some(stem) = file_name.strip_suffix(".log") {
        if standard_hives.iter().any(|&h| stem == h || stem.ends_with(&format!("_{}", h)) || stem.ends_with(&format!("-{}", h))) {
            return true;
        }
    }

    // Registry companions that are never parsed: TxR containers, setup backups
    if file_name.ends_with(".blf") || file_name.ends_with(".regtrans-ms") || file_name.ends_with(".sav") {
        return false;
    }

    // Targeted Linux execution logs
    if file_name == "audit.log" || file_name.starts_with("audit.log.")
        || file_name == "cron" || file_name.starts_with("cron-") || file_name.starts_with("cron.")
        || file_name == "secure" || file_name.starts_with("secure-") || file_name.starts_with("secure.")
        || file_name == "auth.log" || file_name.starts_with("auth.log.")
        || file_name == "dpkg.log" || file_name.starts_with("dpkg.log.")
        || file_name == "yum.log" || file_name.starts_with("yum.log.")
        || file_name.ends_with("access_log") || file_name.ends_with("access.log")
        || file_name == "dmesg.txt" || file_name == "dmesg"
    {
        return true;
    }

    // Linux shell & editor histories (.bash_history, .zsh_history, .viminfo, .nano_history, etc.)
    if file_name.contains("history") || file_name == ".viminfo" || file_name == "main.shada" || file_name.contains("lesshst") {
        return true;
    }

    // Linux process execution triage (ps lstart, /proc/<pid>/*)
    if file_name.starts_with("ps_") || file_name.starts_with("proc_")
        || file_name.contains("cmdline") || file_name.contains("status") || file_name.contains("environ")
        || file_name.contains("running_processes") || file_name == "hostname.txt" || file_name == "hostname"
    {
        return true;
    }

    // Linux package management
    if file_name.contains("installtime") {
        return true;
    }

    // Linux scheduled jobs & persistence (cron, systemd, ssh, pam, sudoers, udev, etc.)
    if file_name.ends_with(".service")
        || file_name.ends_with(".timer")
        || file_name.ends_with(".socket")
        || file_name.ends_with(".path")
        || file_name.ends_with(".rules")
        || file_name.ends_with(".desktop")
        || file_name.ends_with(".bashrc")
        || file_name.ends_with(".profile")
        || file_name.ends_with(".zshrc")
        || file_name == "bash.bashrc"
        || file_name == "profile"
        || file_name == "rc.local"
        || file_name == "environment"
        || file_name == "ld.so.preload"
        || file_name == "authorized_keys"
        || file_name == "authorized_keys2"
        || file_name == "sshd_config"
        || file_name == "sudoers"
        || file_name == "modules"
        || file_name == "crontab"
        || file_name == "anacrontab"
        || file_name.ends_with("profile.ps1")
        || lower.contains("system32/tasks")
        || lower.contains("/tasks/")
        || lower.starts_with("tasks/")
        || lower.contains("cron.d/")
        || lower.contains("spool/cron/")
        || lower.contains("cron.hourly/")
        || lower.contains("cron.daily/")
        || lower.contains("cron.weekly/")
        || lower.contains("cron.monthly/")
        || lower.contains("systemd/")
        || lower.contains("system-generators/")
        || lower.contains("init.d/")
        || lower.contains("profile.d/")
        || lower.contains("sudoers.d/")
        || lower.contains("pam.d/")
        || lower.contains("udev/rules.d/")
        || lower.contains("modprobe.d/")
        || lower.contains("modules-load.d/")
        || lower.contains("apt.conf.d/")
        || lower.contains("autostart/")
        || lower.contains("xdg/")
    {
        return true;
    }

    // Linux process accounting, GUI recently used, web access logs, and crash logs
    if file_name.contains("pacct") || file_name.contains("psacct")
        || file_name == "recently-used.xbel"
        || file_name.contains("segfault") || file_name.contains("coredump")
    {
        return true;
    }

    // Nested archives (excluding VMware drivers)
    if file_name.ends_with(".zip") || file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") || file_name.ends_with(".tar") {
        return true;
    }

    // Triage metadata markers (useful to preserve triage context)
    if file_name == "_kape.cli" || file_name == "client_info.json" || file_name == "manifest.json" {
        return true;
    }

    false
}

/// Reads the top-level entries of a ZIP without deep extraction
pub fn read_zip_top_entries(zip_path: &Path) -> Option<Vec<String>> {
    let file = File::open(zip_path).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            names.push(entry.name().to_string());
        }
    }
    Some(names)
}

/// Inspects an archive to detect triage package type and hostname
pub fn inspect_triage_archive(path: &Path) -> Option<TriageInfo> {
    if !path.exists() {
        return None;
    }
    let path_str = path.to_string_lossy().to_string();
    let entries = read_zip_top_entries(path).unwrap_or_default();
    let kind = detect_triage_type(&path_str, &entries).unwrap_or(TriageType::Generic);
    let hostname = extract_triage_hostname(&path_str, kind);

    Some(TriageInfo {
        kind,
        source_path: path_str,
        hostname,
    })
}

/// Recursively unpacks relevant artifacts from an archive (ZIP, TAR, GZ) into a staging directory
pub fn unpack_archive_recursive(
    archive_path: &Path,
    dest_base: &Path,
    silent: bool,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");

    let target_dir = dest_base.join(stem);
    fs::create_dir_all(&target_dir)?;

    let path_str = archive_path.to_string_lossy().to_lowercase();

    if path_str.ends_with(".zip") {
        unpack_zip(archive_path, &target_dir, silent)?;
    } else if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
        unpack_tar_gz(archive_path, &target_dir, silent)?;
    } else if path_str.ends_with(".tar") {
        unpack_tar(archive_path, &target_dir, silent)?;
    } else {
        return Err(format!(
            "unsupported archive format (only zip, tar, tar.gz/tgz can be unpacked): {}",
            archive_path.display()
        )
        .into());
    }

    // Nested archives (Cortex XDR `<module>-collection/script_output.zip`, Velociraptor
    // `data.zip`, UAC tarballs inside a case zip, …) are unpacked IN PLACE, next to
    // where they were found, so the whole package stays one evidence root: one host,
    // one hive/transaction-log search space, no duplicate processing.
    let nested_linux_roots = scan_and_unpack_nested(&target_dir, silent, 0)?;
    let mut all_dirs = vec![target_dir];
    all_dirs.extend(nested_linux_roots);
    Ok(all_dirs)
}

/// Maximum depth of archive-inside-archive nesting that is unpacked.
pub const MAX_NESTED_ARCHIVE_DEPTH: usize = 4;

/// Folder a nested archive is unpacked into (next to the archive itself).
pub fn nested_extraction_dir(nested_archive: &Path) -> PathBuf {
    let stem = nested_archive
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "nested".to_string());
    let stem = stem
        .strip_suffix(".tar.gz")
        .or_else(|| stem.strip_suffix(".tgz"))
        .or_else(|| stem.strip_suffix(".zip"))
        .or_else(|| stem.strip_suffix(".tar"))
        .unwrap_or(&stem)
        .to_string();
    nested_archive
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{stem}_extracted"))
}

/// Unpacks relevant files from a ZIP archive, attempting known forensic passwords if encrypted
fn unpack_zip(zip_path: &Path, target_dir: &Path, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    // Probe passwords on the first file entry
    let mut working_pwd: Option<&[u8]> = None;
    let entry_count = archive.len();

    let test_idx = (0..entry_count)
        .find(|&i| archive.by_index_raw(i).map(|e| !e.is_dir()).unwrap_or(false))
        .unwrap_or(0);

    for &pwd in FORENSIC_PASSWORDS {
        let f = match File::open(zip_path) {
            Ok(file) => file,
            Err(_) => break,
        };
        let mut probe_archive = match ZipArchive::new(f) {
            Ok(a) => a,
            Err(_) => break,
        };

        let success = if pwd.is_empty() {
            if let Ok(mut e) = probe_archive.by_index(test_idx) {
                let mut buf = [0u8; 4];
                e.read(&mut buf).is_ok()
            } else {
                false
            }
        } else if let Ok(Ok(mut e)) = probe_archive.by_index_decrypt(test_idx, pwd) {
            let mut buf = [0u8; 4];
            e.read(&mut buf).is_ok()
        } else {
            false
        };

        if success {
            working_pwd = Some(pwd);
            if !pwd.is_empty() {
                log_message(
                    silent,
                    &format!(
                        "🔓 Archive is password-protected. Unlocked with known forensic password for: {}",
                        zip_path.display()
                    ),
                );
            }
            break;
        }
    }

    for i in 0..entry_count {
        let mut entry = match working_pwd {
            Some(pwd) if !pwd.is_empty() => match archive.by_index_decrypt(i, pwd) {
                Ok(Ok(e)) => e,
                _ => continue,
            },
            _ => match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            },
        };

        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        if !is_relevant_artifact(&entry_name) {
            continue;
        }

        // Sanitize destination path against directory traversal
        let clean_relative = entry_name.replace("..", "").replace(':', "_");
        let out_path = target_dir.join(clean_relative);

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(mut out_file) = File::create(&out_path) {
            let _ = io::copy(&mut entry, &mut out_file);
        }
    }

    Ok(())
}

/// Unpacks relevant files from a tar.gz / tgz archive
fn unpack_tar_gz(tar_path: &Path, target_dir: &Path, _silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(tar_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = TarArchive::new(gz);

    for entry_res in archive.entries()? {
        let mut entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if !is_relevant_artifact(&path) {
            continue;
        }

        // On Windows, skip symlinks and hardlinks to prevent privilege errors
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }

        let clean_relative = path.replace("..", "").replace(':', "_");
        let out_path = target_dir.join(clean_relative);

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let _ = entry.unpack(&out_path);
    }

    Ok(())
}

/// Unpacks relevant files from an uncompressed tar archive
fn unpack_tar(tar_path: &Path, target_dir: &Path, _silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(tar_path)?;
    let mut archive = TarArchive::new(file);

    for entry_res in archive.entries()? {
        let mut entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if !is_relevant_artifact(&path) {
            continue;
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }

        let clean_relative = path.replace("..", "").replace(':', "_");
        let out_path = target_dir.join(clean_relative);

        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let _ = entry.unpack(&out_path);
    }

    Ok(())
}

/// Unpacks every nested archive found under `extracted_dir` into a sibling
/// `<name>_extracted/` folder and recurses into the result. Returns the nested
/// roots that are Linux targets (they need their own pass, the Windows ones are
/// covered by walking the outer root).
fn scan_and_unpack_nested(extracted_dir: &Path, silent: bool, depth: usize) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if depth >= MAX_NESTED_ARCHIVE_DEPTH {
        return Ok(Vec::new());
    }
    let mut nested_archives = Vec::new();
    for entry in walkdir::WalkDir::new(extracted_dir).into_iter().flatten() {
        let path = entry.path();
        if path.is_file() && is_supported_archive(path) {
            nested_archives.push(path.to_path_buf());
        }
    }

    let mut linux_roots = Vec::new();
    for nested in nested_archives {
        let out_dir = nested_extraction_dir(&nested);
        log_message(silent, &format!("📦 Unpacking nested archive: {} -> {}", nested.display(), out_dir.display()));
        if let Err(e) = fs::create_dir_all(&out_dir) {
            log_message(silent, &format!("⚠️ Warning: cannot create {}: {e}", out_dir.display()));
            continue;
        }
        let lower = nested.to_string_lossy().to_lowercase();
        let result = if lower.ends_with(".zip") {
            unpack_zip(&nested, &out_dir, silent)
        } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            unpack_tar_gz(&nested, &out_dir, silent)
        } else if lower.ends_with(".tar") {
            unpack_tar(&nested, &out_dir, silent)
        } else {
            Err(format!("unsupported nested archive format: {}", nested.display()).into())
        };
        if let Err(e) = result {
            log_message(silent, &format!("⚠️ Warning: failed to unpack nested archive {}: {e}", nested.display()));
            continue;
        }
        // The nested archive has been expanded; drop it so a later walk never re-unpacks it.
        let _ = fs::remove_file(&nested);
        linux_roots.extend(scan_and_unpack_nested(&out_dir, silent, depth + 1)?);
        if crate::parsers::linux::is_linux_target(&out_dir) {
            linux_roots.push(out_dir);
        }
    }
    Ok(linux_roots)
}
