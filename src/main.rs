#![allow(dead_code)]
pub mod errors;
pub mod event;
pub mod csv_out;
pub mod utils;
pub mod parsers;
pub mod ingest;

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use nt_hive2::{
    transactionlog::TransactionLog, BaseBlock, ContainsHive, DirtyHive, Hive, HiveParseMode,
    RegistryValue, SubPath,
};
use walkdir::WalkDir;

const FORMAT_DATE: &str = "%Y-%m-%d %H:%M:%S%.3f";

// ─── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct Persistence {
    timestamp: String,
    technique: String,
    path: String,
    value: String,
    access_gained: String,
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Clone, ValueEnum, Debug, PartialEq)]
enum Action {
    All,
    GetRun,
    GetRunOnce,
    GetRunEx,
    GetRunOnceEx,
    GetImageFileExecutionOptions,
    GetNldpDllOverridePath,
    GetAedebug,
    GetWerFaultHangs,
    GetCmdAutorun,
    GetExplorerLoad,
    GetWinlogonUserinit,
    GetWinlogonShell,
    GetTerminalProfileStartOnUserLogin,
    GetAppCertDlls,
    GetAppPaths,
    GetServiceDlls,
    GetGpExtensionDlls,
    GetWinlogonMpNotify,
    GetChmHelperDll,
    GetStartupPrograms,
    GetScheduledTasks,
    GetWindowsServices,
    GetUserInitMprScript,
    GetHhCtrlHijacking,
    GetAppInitDlls,
    GetLsaPackages,
    GetBootExecute,
    GetActiveSetup,
    GetScreensaver,
    GetSilentProcessExit,
    GetComHijacking,
    GetPrintMonitors,
    GetTimeProviders,
    GetNetshHelperDlls,
    GetPowerShellProfiles,
    GetLinuxPersistence,
}

#[derive(Parser, Debug)]
#[command(
    name = "faramir",
    version = "0.2.0",
    about = "Forensic persistence hunting tool for Windows and Linux triage, images (E01/RAW/ZIP) and offline filesystems"
)]
struct Args {
    /// Directory or drive to process (mounted volume, folder, etc.)
    #[arg(short = 'd', long = "directory", value_name = "DIR")]
    directory: Vec<String>,

    /// Individual files to process (disk images: .E01, .raw, .dd; archives: .zip, .tar.gz; hives)
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    file: Vec<String>,

    /// Output CSV file path
    #[arg(short = 'o', long = "output", value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Legacy flag: Directory where the Windows/Linux machine was mounted
    #[arg(long = "source-evidence")]
    source_evidence: Option<PathBuf>,

    /// Legacy flag: Output CSV file path prefix
    #[arg(long = "csv-output")]
    csv_output: Option<PathBuf>,

    /// Suppress verbose logging
    #[arg(long = "silent")]
    silent: bool,

    /// Action to perform
    #[arg(default_value = "all")]
    action: Action,
}

// ─── Hive helpers ────────────────────────────────────────────────────────────

type HiveFile = Hive<BufReader<File>, nt_hive2::CleanHive>;

fn log_path(hive_path: &Path, suffix: &str) -> PathBuf {
    let mut s = hive_path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn open_hive(path: &Path) -> Option<HiveFile> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let hive: Hive<BufReader<File>, DirtyHive> =
        match std::panic::catch_unwind(|| Hive::new(reader, HiveParseMode::NormalWithBaseBlock)) {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                eprintln!("\x1b[31m[ERROR] Could not parse hive '{}': {e}\x1b[0m", path.display());
                return None;
            }
            Err(_) => {
                eprintln!("\x1b[31m[ERROR] Invalid or corrupt hive file '{}', skipping.\x1b[0m", path.display());
                return None;
            }
        };

    let is_dirty = hive.base_block().map(|bb| bb.is_dirty()).unwrap_or(false);

    if !is_dirty {
        return Some(hive.treat_hive_as_clean());
    }

    println!("\t  [!] Dirty hive detected, applying transaction logs...");

    let log1 = File::open(log_path(path, ".LOG1"))
        .ok()
        .and_then(|f| TransactionLog::try_from(f).ok());
    let log2 = File::open(log_path(path, ".LOG2"))
        .ok()
        .and_then(|f| TransactionLog::try_from(f).ok());

    match (log1, log2) {
        (Some(l1), Some(l2)) => {
            println!("\t    -> Applying LOG1 and LOG2");
            let h = hive.with_transaction_log(l1).ok()?.with_transaction_log(l2).ok()?;
            Some(h.apply_logs())
        }
        (Some(l1), None) => {
            println!("\t    -> Applying LOG1");
            Some(hive.with_transaction_log(l1).ok()?.apply_logs())
        }
        (None, Some(l2)) => {
            println!("\t    -> Applying LOG2");
            Some(hive.with_transaction_log(l2).ok()?.apply_logs())
        }
        (None, None) => {
            println!("\t    [!] No transaction logs found, proceeding with dirty state");
            Some(hive.treat_hive_as_clean())
        }
    }
}

fn fmt_ts(dt: &chrono::DateTime<Utc>) -> String {
    dt.format(FORMAT_DATE).to_string()
}

/// Try to navigate to `key_path` in the hive at `hive_path`.
/// Calls `f(key_node, &mut hive)` if found.
/// Returns Vec<Persistence> collected by `f`.
macro_rules! with_key {
    ($hive_path:expr, $key_path:expr, |$key:ident, $hive:ident| $body:expr) => {{
        let mut result: Vec<Persistence> = Vec::new();
        if let Some(mut $hive) = open_hive($hive_path) {
            if let Ok(root) = $hive.root_key_node() {
                if let Ok(Some(key_rc)) = root.subpath($key_path, &mut $hive) {
                    let $key = key_rc.borrow();
                    result.extend($body);
                }
            }
        }
        result
    }};
}

fn get_hives(source: &Path) -> Vec<PathBuf> {
    let system_hive_names = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
    let mut hives = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if system_hive_names.contains(&name.as_str())
            || name.starts_with("NTUSER")
        {
            println!("\t{}", path.display());
            hives.push(path.to_path_buf());
        }
    }

    hives
}

// ─── Techniques ──────────────────────────────────────────────────────────────

fn run_key_entries(
    hives: &[PathBuf],
    key_paths: &[(&str, &str)], // (path, access_gained)
    technique: &str,
) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in key_paths {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                let ts = fmt_ts(key.timestamp());
                key.values()
                    .iter()
                    .filter_map(|v| match v.value() {
                        RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) => {
                            println!("\t{s}");
                            Some(Persistence {
                                timestamp: ts.clone(),
                                path: hive_path.to_string_lossy().to_string(),
                                access_gained: access.to_string(),
                                technique: technique.to_string(),
                                value: s.clone(),
                            })
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_run(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Run Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "User"),
            (r"Microsoft\Windows\CurrentVersion\Run", "System"),
        ],
        "Registry Run Key",
    )
}

fn get_runonce(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting RunOnce Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "User"),
            (r"Microsoft\Windows\CurrentVersion\RunOnce", "System"),
        ],
        "Registry RunOnce Key",
    )
}

fn get_runex(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting RunEx Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx", "User"),
            (r"Microsoft\Windows\CurrentVersion\RunEx", "System"),
        ],
        "Registry RunEx Key",
    )
}

fn get_runonceex(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting RunOnceEx Persistence");
    run_key_entries(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", "User"),
            (r"Microsoft\Windows\CurrentVersion\RunOnceEx", "System"),
        ],
        "Registry RunOnceEx Key",
    )
}

fn get_image_file_execution_options(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Image File Execution Options");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            |key, hive| {
                let mut entries = Vec::new();
                if let Ok(subkeys) = key.subkeys(&mut hive) {
                    for image_rc in subkeys.iter() {
                        let image = image_rc.borrow();
                        let ts = fmt_ts(image.timestamp());
                        for v in image.values() {
                            if v.name() == "Debugger" {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    println!("\t{s}");
                                    entries.push(Persistence {
                                        timestamp: ts.clone(),
                                        path: s.clone(),
                                        access_gained: "System/User".to_string(),
                                        technique: "Image file execution options".to_string(),
                                        value: s.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_nldp_dll_override_path(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Natural Language Development Platform DLL path override properties.");
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            // Read current control set number
            let current: u32 = if let Ok(Some(sel_rc)) = root.subpath("Select", &mut hive) {
                sel_rc
                    .borrow()
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("Current"))
                    .and_then(|v| {
                        if let RegistryValue::RegDWord(n) = v.value() {
                            Some(*n)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(1)
            } else {
                continue;
            };

            let lang_path = format!(r"ControlSet{current:03}\Control\ContentIndex\Language");
            let Ok(Some(langs_rc)) = root.subpath(lang_path.as_str(), &mut hive) else {
                continue;
            };
            let langs = langs_rc.borrow();
            let Ok(subkeys) = langs.subkeys(&mut hive) else { continue };
            for lang_rc in subkeys.iter() {
                let lang = lang_rc.borrow();
                let ts = fmt_ts(lang.timestamp());
                let stemmer = lang
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("StemmerDLLPathOverride"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                let wb = lang
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("WBDLLPathOverride"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                if stemmer.is_some() || wb.is_some() {
                    let val = wb.clone().unwrap_or_default();
                    println!("\t{val}");
                    result.push(Persistence {
                        timestamp: ts,
                        path: stemmer.unwrap_or_default(),
                        access_gained: String::new(),
                        technique: "Natural Language Development Platform 6 DLL Override Path"
                            .to_string(),
                        value: val,
                    });
                }
            }
        }
    }
    result
}

fn aedebug_entries(hives: &[PathBuf], key_path: &str) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, key_path, |key, hive| {
            let mut entries = Vec::new();
            if let Ok(subkeys) = key.subkeys(&mut hive) {
                for sub_rc in subkeys.iter() {
                    let sub = sub_rc.borrow();
                    let ts = fmt_ts(sub.timestamp());
                    for v in sub.values() {
                        let path_str = format!("Name: {} Value: {}", v.name(), v.value());
                        println!("\t{path_str}");
                        entries.push(Persistence {
                            timestamp: ts.clone(),
                            path: path_str,
                            access_gained: "System".to_string(),
                            technique: "AEDebug Custom Debugger".to_string(),
                            value: "AeDebug".to_string(),
                        });
                    }
                }
            }
            entries
        }));
    }
    result
}

fn get_aedebug(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting AeDebug properties.");
    let mut result = Vec::new();
    result.extend(aedebug_entries(
        hives,
        r"Microsoft\Windows NT\CurrentVersion\AeDebug",
    ));
    result.extend(aedebug_entries(
        hives,
        r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug",
    ));
    result
}

fn werfault_entries(hives: &[PathBuf], key_path: &str) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, key_path, |key, hive| {
            let mut entries = Vec::new();
            if let Ok(subkeys) = key.subkeys(&mut hive) {
                for sub_rc in subkeys.iter() {
                    let sub = sub_rc.borrow();
                    let ts = fmt_ts(sub.timestamp());
                    for v in sub.values() {
                        let path_str = format!("Name: {} Value: {}", v.name(), v.value());
                        println!("\t{path_str}");
                        entries.push(Persistence {
                            timestamp: ts.clone(),
                            path: path_str,
                            access_gained: "System".to_string(),
                            technique: "Windows Error Reporting Debugger".to_string(),
                            value: "werfaultDebuggger".to_string(),
                        });
                    }
                }
            }
            entries
        }));
    }
    result
}

fn get_wer_fault_hangs(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting WerFault Hangs registry key Debug property.");
    let mut result = Vec::new();
    result.extend(werfault_entries(
        hives,
        r"Microsoft\Windows\Windows Error Reporting\Hangs",
    ));
    result.extend(werfault_entries(
        hives,
        r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs",
    ));
    result
}

fn get_cmd_autorun(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Command Processor's AutoRun property.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in &[
            (r"Software\Microsoft\Command Processor", "User"),
            (r"Microsoft\Command Processor", "User"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                key.values()
                    .iter()
                    .filter(|v| v.name().eq_ignore_ascii_case("Autorun"))
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            let path_str = format!("Name: {s}");
                            println!("\t{path_str}");
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: path_str,
                                access_gained: access.to_string(),
                                technique: "Command Processor AutoRun key".to_string(),
                                value: "CmdAutoRun".to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn single_value_key(
    hives: &[PathBuf],
    key_paths: &[(&str, &str)],
    value_name: &str,
    technique: &str,
    persistence_value: &str,
) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in key_paths {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                key.values()
                    .iter()
                    .filter(|v| v.name().eq_ignore_ascii_case(value_name))
                    .map(|v| {
                        let path_str =
                            format!("Name: {} Value: {}", v.name(), v.value());
                        println!("\t{path_str}");
                        Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: path_str,
                            access_gained: access.to_string(),
                            technique: technique.to_string(),
                            value: persistence_value.to_string(),
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_explorer_load(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Explorer's Load property.");
    single_value_key(
        hives,
        &[
            (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "System"),
            (r"Microsoft\Windows NT\CurrentVersion\Windows", "System"),
        ],
        "Load",
        "Explorer Load Property",
        "ExplorerLoad",
    )
}

fn get_winlogon_userinit(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Winlogon's Userinit property.");
    single_value_key(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
        ],
        "Userinit",
        "Winlogon Userinit Property",
        "WinLogonUserInit",
    )
}

fn get_winlogon_shell(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Winlogon's Shell property.");
    single_value_key(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
        ],
        "Shell",
        "Winlogon shell Property",
        "WinLogonShell",
    )
}

fn get_terminal_profile_start_on_user_login(settings_files: &[PathBuf]) -> Vec<Persistence> {
    println!(
        "+ Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value."
    );
    let mut result = Vec::new();
    for file in settings_files {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        let Ok(data): Result<serde_json::Value, _> = serde_json::from_str(&content) else {
            continue;
        };
        let profiles = &data["profiles"];
        let list = if profiles.is_object() {
            profiles["list"].as_array().cloned().unwrap_or_default()
        } else if profiles.is_array() {
            profiles.as_array().cloned().unwrap_or_default()
        } else {
            continue;
        };
        for profile in &list {
            if profile.get("startOnUserLogin") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let commandline = profile
                .get("commandline")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
                .to_string();
            let ts = file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| {
                    let secs = t
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)?;
                    chrono::DateTime::from_timestamp(secs, 0)
                })
                .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                .unwrap_or_default();
            println!("\t{commandline}");
            result.push(Persistence {
                timestamp: ts,
                path: file.to_string_lossy().to_string(),
                access_gained: "User".to_string(),
                technique: "Windows Terminal startOnUserLogin".to_string(),
                value: commandline,
            });
        }
    }
    result
}

fn all_values_key(
    hives: &[PathBuf],
    key_paths: &[(&str, &str)],
    technique: &str,
    persistence_value: &str,
) -> Vec<Persistence> {
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in key_paths {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                key.values()
                    .iter()
                    .map(|v| {
                        let path_str =
                            format!("{} {}", v.name(), v.value());
                        println!("\t{path_str}");
                        Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: path_str,
                            access_gained: access.to_string(),
                            technique: technique.to_string(),
                            value: persistence_value.to_string(),
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_app_cert_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting AppCertDlls properties.");
    all_values_key(
        hives,
        &[
            (r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls", "User"),
            (r"CurrentControlSet\Control\Session Manager\AppCertDlls", "System"),
        ],
        "AppCertDlls properties.",
        "AppCertDlls",
    )
}

fn get_app_paths(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting App Paths inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in &[
            (r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", "User"),
            (r"Microsoft\Windows\CurrentVersion\App Paths", "System"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(apps) = key.subkeys(&mut hive) {
                    for app_rc in apps.iter() {
                        let app = app_rc.borrow();
                        let exe_path = app
                            .values()
                            .iter()
                            .find(|v| v.name().is_empty() || v.name() == "(default)")
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            });
                        if let Some(path_str) = exe_path {
                            println!("\t{path_str}");
                            entries.push(Persistence {
                                timestamp: fmt_ts(app.timestamp()),
                                path: path_str,
                                access_gained: access.to_string(),
                                technique: "App Paths".to_string(),
                                value: app.name().to_string(),
                            });
                        }
                    }
                }
                entries
            }));
        }
    }
    result
}

fn get_service_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Service DLLs inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            let current = get_current_control_set(&root, &mut hive).unwrap_or(1);
            let services_path = format!(r"ControlSet{current:03}\Services");
            let Ok(Some(services_rc)) = root.subpath(services_path.as_str(), &mut hive) else {
                continue;
            };
            let services = services_rc.borrow();
            let Ok(service_keys) = services.subkeys(&mut hive) else { continue };
            for svc_rc in service_keys.iter() {
                let svc = svc_rc.borrow();
                let ts = fmt_ts(svc.timestamp());
                let dll = svc
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("ServiceDll"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });

                // Also check Parameters subkey
                let params_dll = if let Ok(params) = svc.subkeys(&mut hive) {
                    params
                        .iter()
                        .find(|k| k.borrow().name().eq_ignore_ascii_case("Parameters"))
                        .and_then(|p_rc| {
                            p_rc.borrow()
                                .values()
                                .iter()
                                .find(|v| v.name().eq_ignore_ascii_case("ServiceDll"))
                                .and_then(|v| {
                                    if let RegistryValue::RegSZ(s)
                                    | RegistryValue::RegExpandSZ(s) = v.value()
                                    {
                                        Some(s.clone())
                                    } else {
                                        None
                                    }
                                })
                        })
                } else {
                    None
                };

                let dll_path = params_dll.or(dll);
                if let Some(d) = dll_path {
                    println!("\t{d}");
                    result.push(Persistence {
                        timestamp: ts,
                        path: d.clone(),
                        access_gained: "System".to_string(),
                        technique: "ServiceDll Hijacking".to_string(),
                        value: "ServiceDlls".to_string(),
                    });
                }
            }
        }
    }
    result
}

fn get_gp_extension_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Group Policy Extension DLLs inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, access) in &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "User"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "System"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(subkeys) = key.subkeys(&mut hive) {
                    for ext_rc in subkeys.iter() {
                        let ext = ext_rc.borrow();
                        let ts = fmt_ts(ext.timestamp());
                        for v in ext.values() {
                            if v.name().eq_ignore_ascii_case("DllName") {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    println!("\t{s}");
                                    entries.push(Persistence {
                                        timestamp: ts.clone(),
                                        path: s.clone(),
                                        access_gained: access.to_string(),
                                        technique: "Group Policy Extension DLL".to_string(),
                                        value: "Group Policy Extension DLL".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                entries
            }));
        }
    }
    result
}

fn get_winlogon_mpnotify(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Winlogon MPNotify property.");
    single_value_key(
        hives,
        &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "User"),
            (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
        ],
        "mpnotify",
        "MPNotify",
        "MPNotify",
    )
}

fn get_chm_helper_dll(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting CHM Helper DLL inside the registry.");
    all_values_key(
        hives,
        &[
            (r"Software\Microsoft\HtmlHelp Author", "User"),
            (r"Microsoft\HtmlHelp Author", "System"),
        ],
        "CHMHelperDll",
        "CHMHelperDll",
    )
}

fn get_startup_programs(startup_files: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Checking if users' Startup folder contains interesting artifacts.");
    startup_files
        .iter()
        .map(|program| {
            let ts = program
                .metadata()
                .ok()
                .and_then(|m| m.created().ok())
                .and_then(|t| {
                    let secs = t
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)?;
                    chrono::DateTime::from_timestamp(secs, 0)
                })
                .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                .unwrap_or_default();
            println!("\t{}", program.display());
            Persistence {
                timestamp: ts,
                path: program.to_string_lossy().to_string(),
                access_gained: "User".to_string(),
                technique: "Startup Folder".to_string(),
                value: "Startup Folder".to_string(),
            }
        })
        .collect()
}

fn get_scheduled_tasks(hives: &[PathBuf], source_evidence: Option<&Path>) -> Vec<Persistence> {
    println!("+ Getting scheduled tasks.");
    let mut result = Vec::new();

    // Registry
    for hive_path in hives {
        for (key_path, access) in &[
            (r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "System"),
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "User"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(tasks) = key.subkeys(&mut hive) {
                    for task_rc in tasks.iter() {
                        let task = task_rc.borrow();
                        let ts = fmt_ts(task.timestamp());
                        if let Some(path_val) = task
                            .values()
                            .iter()
                            .find(|v| v.name().eq_ignore_ascii_case("Path"))
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            })
                        {
                            println!("\t{path_val}");
                            entries.push(Persistence {
                                timestamp: ts,
                                path: path_val,
                                access_gained: access.to_string(),
                                technique: "Scheduled Task".to_string(),
                                value: "Scheduled Task".to_string(),
                            });
                        }
                    }
                }
                entries
            }));
        }
    }

    // XML files on filesystem — walk recursively, collect files inside any "Tasks" directory
    if let Some(source) = source_evidence {
        for entry in WalkDir::new(source).into_iter().flatten() {
            let path = entry.path();
            let in_tasks = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().eq_ignore_ascii_case("Tasks"))
                .unwrap_or(false);
            if !path.is_file() || !in_tasks {
                continue;
            }
            {
                let Ok(content) = std::fs::read_to_string(path) else {
                    continue;
                };
                let Ok(doc) = roxmltree::Document::parse(&content) else {
                    continue;
                };
                let ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
                let command = doc
                    .descendants()
                    .find(|n| n.has_tag_name((ns, "Command")))
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if command.is_empty() {
                    continue;
                }
                let args = doc
                    .descendants()
                    .find(|n| n.has_tag_name((ns, "Arguments")))
                    .and_then(|n| n.text())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let full_cmd = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{command} {args}")
                };
                let ts = path
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| {
                        let secs = t
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs() as i64)?;
                        chrono::DateTime::from_timestamp(secs, 0)
                    })
                    .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                    .unwrap_or_default();
                println!("\t{full_cmd}");
                result.push(Persistence {
                    timestamp: ts,
                    path: path.to_string_lossy().to_string(),
                    access_gained: "System".to_string(),
                    technique: "Scheduled Task (XML)".to_string(),
                    value: full_cmd,
                });
            }
        }
    }
    result
}

fn get_windows_services(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Checking Windows Services.");
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            let current = get_current_control_set(&root, &mut hive).unwrap_or(1);
            let services_path = format!(r"ControlSet{current:03}\Services");
            let Ok(Some(services_rc)) = root.subpath(services_path.as_str(), &mut hive) else {
                continue;
            };
            let services = services_rc.borrow();
            let Ok(service_keys) = services.subkeys(&mut hive) else { continue };
            for svc_rc in service_keys.iter() {
                let svc = svc_rc.borrow();
                let ts = fmt_ts(svc.timestamp());
                let image_path = svc
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("ImagePath"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });
                let has_service_dll = svc
                    .values()
                    .iter()
                    .any(|v| v.name().eq_ignore_ascii_case("ServiceDll"));
                let display_name = svc
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("DisplayName"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();
                if !has_service_dll {
                    if let Some(img) = image_path {
                        println!("\t{img}");
                        result.push(Persistence {
                            timestamp: ts,
                            path: img,
                            access_gained: "System".to_string(),
                            technique: "Windows Service".to_string(),
                            value: display_name,
                        });
                    }
                }
            }
        }
    }
    result
}

fn get_user_init_mpr_script(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting users' UserInitMprLogonScript property.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, "Environment", |key, _hive| {
            key.values()
                .iter()
                .filter(|v| v.name().eq_ignore_ascii_case("UserInitMprLogonScript"))
                .filter_map(|v| {
                    if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                        let path_str = format!("{} {s}", v.name());
                        println!("\t{path_str}");
                        Some(Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: path_str,
                            access_gained: "User".to_string(),
                            technique: "User Init Mpr Logon Script".to_string(),
                            value: s.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        }));
    }
    result
}

fn get_hhctrl_hijacking(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting the hhctrl.ocx library inside the registry.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"Classes\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32",
            |key, _hive| {
                key.values()
                    .iter()
                    .filter(|v| v.name().is_empty() || v.name() == "(default)")
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            let path_str = format!("{} {s}", v.name());
                            println!("\t{path_str}");
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: path_str,
                                access_gained: "System".to_string(),
                                technique: "Hijacking of hhctrl.ocx".to_string(),
                                value: s.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }
        ));
    }
    result
}

fn get_app_init_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting AppInit_DLLs property.");
    let mut result = Vec::new();
    for hive_path in hives {
        for (key_path, technique) in &[
            (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit DLLs"),
            (r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit DLLs (Wow6432Node)"),
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, _hive| {
                let load_flag = key
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("LoadAppInit_DLLs"))
                    .and_then(|v| {
                        if let RegistryValue::RegDWord(n) = v.value() {
                            Some(*n)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(1);
                if load_flag == 0 {
                    return vec![];
                }
                key.values()
                    .iter()
                    .filter(|v| v.name().eq_ignore_ascii_case("AppInit_DLLs"))
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value()
                        {
                            if s.trim().is_empty() {
                                return None;
                            }
                            println!("\t{s}");
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: key_path.to_string(),
                                access_gained: "System".to_string(),
                                technique: technique.to_string(),
                                value: s.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }));
        }
    }
    result
}

fn get_lsa_packages(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting LSA Authentication, Security and Notification Packages.");
    let defaults = ["", "msv1_0", "scecli", "rassfm"];
    let lsa_values = [
        ("Authentication Packages", "System"),
        ("Security Packages", "System"),
        ("Notification Packages", "System"),
    ];
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            |key, _hive| {
                let ts = fmt_ts(key.timestamp());
                let mut entries = Vec::new();
                for (value_name, access) in &lsa_values {
                    if let Some(v) = key
                        .values()
                        .iter()
                        .find(|v| v.name().eq_ignore_ascii_case(value_name))
                    {
                        if let RegistryValue::RegMultiSZ(packages) = v.value() {
                            for pkg in packages {
                                let pkg = pkg.trim();
                                if pkg.is_empty()
                                    || defaults.iter().any(|d| d.eq_ignore_ascii_case(pkg))
                                {
                                    continue;
                                }
                                println!("\t{pkg}");
                                entries.push(Persistence {
                                    timestamp: ts.clone(),
                                    path: r"SYSTEM\CurrentControlSet\Control\Lsa".to_string(),
                                    access_gained: access.to_string(),
                                    technique: format!("LSA {value_name}"),
                                    value: pkg.to_string(),
                                });
                            }
                        }
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_boot_execute(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting BootExecute property.");
    let defaults = ["autocheck autochk *", "autocheck autochk*", ""];
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            |key, _hive| {
                let ts = fmt_ts(key.timestamp());
                let mut entries = Vec::new();
                if let Some(v) = key
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("BootExecute"))
                {
                    let items: Vec<String> = match v.value() {
                        RegistryValue::RegMultiSZ(list) => list.clone(),
                        RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) => {
                            vec![s.clone()]
                        }
                        _ => vec![],
                    };
                    for entry in items {
                        let entry = entry.trim();
                        if defaults.iter().any(|d| d.eq_ignore_ascii_case(entry)) {
                            continue;
                        }
                        println!("\t{entry}");
                        entries.push(Persistence {
                            timestamp: ts.clone(),
                            path: r"SYSTEM\CurrentControlSet\Control\Session Manager".to_string(),
                            access_gained: "System".to_string(),
                            technique: "Boot Execute".to_string(),
                            value: entry.to_string(),
                        });
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_active_setup(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Active Setup Installed Components.");
    let mut result = Vec::new();
    for hive_path in hives {
        for key_path in &[
            r"SOFTWARE\Microsoft\Active Setup\Installed Components",
            r"SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
        ] {
            result.extend(with_key!(hive_path, *key_path, |key, hive| {
                let mut entries = Vec::new();
                if let Ok(subkeys) = key.subkeys(&mut hive) {
                    for comp_rc in subkeys.iter() {
                        let comp = comp_rc.borrow();
                        let stub = comp
                            .values()
                            .iter()
                            .find(|v| v.name().eq_ignore_ascii_case("StubPath"))
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    let s = s.trim().to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                } else {
                                    None
                                }
                            });
                        if let Some(stub_path) = stub {
                            println!("\t{stub_path}");
                            entries.push(Persistence {
                                timestamp: fmt_ts(comp.timestamp()),
                                path: format!(r"{key_path}\{}", comp.name()),
                                access_gained: "System".to_string(),
                                technique: "Active Setup StubPath".to_string(),
                                value: stub_path,
                            });
                        }
                    }
                }
                entries
            }));
        }
    }
    result
}

fn get_screensaver(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Screensaver persistence.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, r"Control Panel\Desktop", |key, _hive| {
            key.values()
                .iter()
                .find(|v| v.name().eq_ignore_ascii_case("SCRNSAVE.EXE"))
                .and_then(|v| {
                    if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                        let s = s.trim().to_string();
                        if s.is_empty() { return None; }
                        println!("\t{s}");
                        Some(Persistence {
                            timestamp: fmt_ts(key.timestamp()),
                            path: hive_path.to_string_lossy().to_string(),
                            access_gained: "User".to_string(),
                            technique: "Screensaver".to_string(),
                            value: s,
                        })
                    } else { None }
                })
                .into_iter()
                .collect::<Vec<_>>()
        }));
    }
    result
}

fn get_silent_process_exit(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting SilentProcessExit persistence.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
            |key, hive| {
                let mut entries = Vec::new();
                if let Ok(monitored_keys) = key.subkeys(&mut hive) {
                    for mon_rc in monitored_keys.iter() {
                        let mon = mon_rc.borrow();
                        let ts = fmt_ts(mon.timestamp());
                        let monitor_process = mon
                            .values()
                            .iter()
                            .find(|v| v.name().eq_ignore_ascii_case("MonitorProcess"))
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    let s = s.trim().to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                } else {
                                    None
                                }
                            });
                        if let Some(proc) = monitor_process {
                            println!("\t{} -> {proc}", mon.name());
                            entries.push(Persistence {
                                timestamp: ts,
                                path: format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{}", mon.name()),
                                access_gained: "System".to_string(),
                                technique: "Silent Process Exit Monitor".to_string(),
                                value: proc,
                            });
                        }
                    }
                }
                entries
            }
        ));
    }
    result
}

fn get_com_hijacking(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting COM Object hijacking (HKCU Classes).");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(hive_path, r"Software\Classes\CLSID", |key, hive| {
            let mut entries = Vec::new();
            if let Ok(clsids) = key.subkeys(&mut hive) {
                for clsid_rc in clsids.iter() {
                    let clsid = clsid_rc.borrow();
                    let inproc = if let Ok(sub) = clsid.subkeys(&mut hive) {
                        sub.iter()
                            .find(|k| k.borrow().name().eq_ignore_ascii_case("InprocServer32"))
                            .cloned()
                    } else {
                        None
                    };
                    if let Some(inproc_rc) = inproc {
                        let inproc = inproc_rc.borrow();
                        let ts = fmt_ts(inproc.timestamp());
                        let dll = inproc
                            .values()
                            .iter()
                            .find(|v| v.name().is_empty() || v.name() == "(default)")
                            .and_then(|v| {
                                if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) =
                                    v.value()
                                {
                                    let s = s.trim().to_string();
                                    if s.is_empty() { None } else { Some(s) }
                                } else {
                                    None
                                }
                            });
                        if let Some(dll_path) = dll {
                            println!("\t{} -> {dll_path}", clsid.name());
                            entries.push(Persistence {
                                timestamp: ts,
                                path: format!(r"Software\Classes\CLSID\{}\InprocServer32", clsid.name()),
                                access_gained: "User".to_string(),
                                technique: "COM Object Hijacking".to_string(),
                                value: dll_path,
                            });
                        }
                    }
                }
            }
            entries
        }));
    }
    result
}

fn get_print_monitors(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Print Monitors.");
    let standard_monitors = [
        "Local Port",
        "Standard TCP/IP Port",
        "USB Monitor",
        "WSD Port",
        "Microsoft Shared Fax Monitor",
    ];
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            let current = get_current_control_set(&root, &mut hive).unwrap_or(1);
            let mon_path = format!(r"ControlSet{current:03}\Control\Print\Monitors");
            let Ok(Some(mon_rc)) = root.subpath(mon_path.as_str(), &mut hive) else {
                continue;
            };
            let mon_key = mon_rc.borrow();
            let Ok(subkeys) = mon_key.subkeys(&mut hive) else { continue };
            for sub_rc in subkeys.iter() {
                let sub = sub_rc.borrow();
                let name = sub.name();
                if standard_monitors.iter().any(|&s| s.eq_ignore_ascii_case(name)) {
                    continue;
                }
                let ts = fmt_ts(sub.timestamp());
                let driver = sub
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("Driver"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| name.to_string());

                println!("\t{name} -> {driver}");
                result.push(Persistence {
                    timestamp: ts,
                    path: format!(r"SYSTEM\ControlSet{current:03}\Control\Print\Monitors\{name}"),
                    access_gained: "System".to_string(),
                    technique: "Print Monitor DLL".to_string(),
                    value: driver,
                });
            }
        }
    }
    result
}

fn get_time_providers(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting W32Time Time Providers.");
    let standard_dlls = ["w32time.dll", "vmictimeprovider.dll"];
    let mut result = Vec::new();
    for hive_path in hives {
        if let Some(mut hive) = open_hive(hive_path) {
            let Ok(root) = hive.root_key_node() else { continue };
            let current = get_current_control_set(&root, &mut hive).unwrap_or(1);
            let tp_path = format!(r"ControlSet{current:03}\Services\W32Time\TimeProviders");
            let Ok(Some(tp_rc)) = root.subpath(tp_path.as_str(), &mut hive) else {
                continue;
            };
            let tp_key = tp_rc.borrow();
            let Ok(subkeys) = tp_key.subkeys(&mut hive) else { continue };
            for sub_rc in subkeys.iter() {
                let sub = sub_rc.borrow();
                let name = sub.name();
                let ts = fmt_ts(sub.timestamp());
                let dll = sub
                    .values()
                    .iter()
                    .find(|v| v.name().eq_ignore_ascii_case("DllName"))
                    .and_then(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                            Some(s.clone())
                        } else {
                            None
                        }
                    });

                if let Some(dll_name) = dll {
                    let is_standard = standard_dlls.iter().any(|&s| dll_name.to_lowercase().ends_with(s));
                    if !is_standard {
                        println!("\t{name} -> {dll_name}");
                        result.push(Persistence {
                            timestamp: ts,
                            path: format!(r"SYSTEM\ControlSet{current:03}\Services\W32Time\TimeProviders\{name}"),
                            access_gained: "System".to_string(),
                            technique: "Time Provider DLL".to_string(),
                            value: dll_name,
                        });
                    }
                }
            }
        }
    }
    result
}

fn get_netsh_helper_dlls(hives: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Getting Netsh Helper DLLs.");
    let mut result = Vec::new();
    for hive_path in hives {
        result.extend(with_key!(
            hive_path,
            r"SOFTWARE\Microsoft\NetSh",
            |key, _hive| {
                key.values()
                    .iter()
                    .filter_map(|v| {
                        if let RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) = v.value() {
                            println!("\t{} -> {s}", v.name());
                            Some(Persistence {
                                timestamp: fmt_ts(key.timestamp()),
                                path: format!(r"SOFTWARE\Microsoft\NetSh\{}", v.name()),
                                access_gained: "System".to_string(),
                                technique: "Netsh Helper DLL".to_string(),
                                value: s.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            }
        ));
    }
    result
}

fn get_powershell_profiles(source: &Path) -> Vec<Persistence> {
    println!("+ Checking for PowerShell Profile scripts...");
    let mut result = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if fname.ends_with("profile.ps1") {
            let ts = path
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| {
                    let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
                    chrono::DateTime::from_timestamp(secs, 0)
                })
                .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
                .unwrap_or_default();

            println!("\tFound PowerShell profile: {}", path.display());
            result.push(Persistence {
                timestamp: ts,
                path: path.to_string_lossy().to_string(),
                access_gained: "User".to_string(),
                technique: "PowerShell Profile Script".to_string(),
                value: path.to_string_lossy().to_string(),
            });
        }
    }
    result
}

// ─── Helper: current control set ─────────────────────────────────────────────

fn get_current_control_set(root: &nt_hive2::KeyNode, hive: &mut HiveFile) -> Option<u32> {
    let sel_rc = root.subpath("Select", hive).ok()??;
    let sel = sel_rc.borrow();
    let result = sel
        .values()
        .iter()
        .find(|v| v.name().eq_ignore_ascii_case("Current"))
        .and_then(|v| {
            if let RegistryValue::RegDWord(n) = v.value() {
                Some(*n)
            } else {
                None
            }
        });
    result
}

// ─── File discovery ──────────────────────────────────────────────────────────

fn get_settings_json_files(source: &Path) -> Vec<PathBuf> {
    println!("+ Searching for settings.json files...");
    let mut files = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if entry.file_name() != "settings.json" || !path.is_file() {
            continue;
        }
        // Only Windows Terminal settings files (parent dir is LocalState,
        // grandparent contains "Microsoft.WindowsTerminal")
        let is_terminal = path
            .ancestors()
            .any(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().contains("Microsoft.WindowsTerminal"))
                    .unwrap_or(false)
            });
        if is_terminal {
            println!("\tFound settings.json: {}", path.display());
            files.push(path.to_path_buf());
        }
    }

    if files.is_empty() {
        println!("No settings.json files found.");
    }
    files
}

fn get_startup_files(source: &Path) -> Vec<PathBuf> {
    println!("+ Searching for startup files...");
    let mut files = Vec::new();

    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // File must be inside a directory named exactly "Startup"
        let in_startup = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("Startup"))
            .unwrap_or(false);
        if in_startup {
            println!("\tFound startup file: {}", path.display());
            files.push(path.to_path_buf());
        }
    }

    if files.is_empty() {
        println!("No startup files found.");
    }
    files
}

// ─── Output ──────────────────────────────────────────────────────────────────

fn write_csv(persistences: &[Persistence], prefix: &Path) -> Result<()> {
    let out_path = prefix.join("faramir.output.csv");
    let mut wtr = csv::Writer::from_path(&out_path)?;
    wtr.write_record(["Timestamp", "Path", "AccessGained", "Technique", "Value"])?;
    for p in persistences {
        wtr.write_record([
            &p.timestamp,
            &p.path,
            &p.access_gained,
            &p.technique,
            &p.value,
        ])?;
    }
    wtr.flush()?;
    println!("Output written to {}", out_path.display());
    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn run_all(hives: &[PathBuf], source: &Path) -> Vec<Persistence> {
    let mut all: Vec<Persistence> = Vec::new();
    if !hives.is_empty() {
        all.extend(get_run(hives));
        all.extend(get_runonce(hives));
        all.extend(get_runex(hives));
        all.extend(get_runonceex(hives));
        all.extend(get_image_file_execution_options(hives));
        all.extend(get_nldp_dll_override_path(hives));
        all.extend(get_aedebug(hives));
        all.extend(get_wer_fault_hangs(hives));
        all.extend(get_cmd_autorun(hives));
        all.extend(get_explorer_load(hives));
        all.extend(get_winlogon_userinit(hives));
        all.extend(get_winlogon_shell(hives));
        all.extend(get_app_cert_dlls(hives));
        all.extend(get_app_paths(hives));
        all.extend(get_service_dlls(hives));
        all.extend(get_gp_extension_dlls(hives));
        all.extend(get_winlogon_mpnotify(hives));
        all.extend(get_chm_helper_dll(hives));
        all.extend(get_windows_services(hives));
        all.extend(get_user_init_mpr_script(hives));
        all.extend(get_hhctrl_hijacking(hives));
        all.extend(get_app_init_dlls(hives));
        all.extend(get_lsa_packages(hives));
        all.extend(get_boot_execute(hives));
        all.extend(get_active_setup(hives));
        all.extend(get_screensaver(hives));
        all.extend(get_silent_process_exit(hives));
        all.extend(get_com_hijacking(hives));
        all.extend(get_print_monitors(hives));
        all.extend(get_time_providers(hives));
        all.extend(get_netsh_helper_dlls(hives));
    }
    let settings_files = get_settings_json_files(source);
    all.extend(get_terminal_profile_start_on_user_login(&settings_files));
    let startup_files = get_startup_files(source);
    all.extend(get_startup_programs(&startup_files));
    all.extend(get_scheduled_tasks(hives, Some(source)));
    all.extend(get_powershell_profiles(source));
    all
}

fn persistence_to_event(p: &Persistence, computer_name: &str) -> event::Event {
    let processname = if p.value.contains('\\') || p.value.contains('/') {
        p.value
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&p.value)
            .split_whitespace()
            .next()
            .unwrap_or(&p.value)
            .to_string()
    } else {
        p.value.split_whitespace().next().unwrap_or(&p.value).to_string()
    };

    let clean_tech = p
        .technique
        .to_lowercase()
        .replace([' ', '(', ')', '/', '.'], "_");
    let artifact = format!("windows:persistence:{}", clean_tech);

    event::Event {
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

fn execute_action(action: &Action, hives: &[PathBuf], source: Option<&Path>) -> Vec<Persistence> {
    match action {
        Action::GetRun => get_run(hives),
        Action::GetRunOnce => get_runonce(hives),
        Action::GetRunEx => get_runex(hives),
        Action::GetRunOnceEx => get_runonceex(hives),
        Action::GetImageFileExecutionOptions => get_image_file_execution_options(hives),
        Action::GetNldpDllOverridePath => get_nldp_dll_override_path(hives),
        Action::GetAedebug => get_aedebug(hives),
        Action::GetWerFaultHangs => get_wer_fault_hangs(hives),
        Action::GetCmdAutorun => get_cmd_autorun(hives),
        Action::GetExplorerLoad => get_explorer_load(hives),
        Action::GetWinlogonUserinit => get_winlogon_userinit(hives),
        Action::GetWinlogonShell => get_winlogon_shell(hives),
        Action::GetTerminalProfileStartOnUserLogin => {
            let files = source.map(get_settings_json_files).unwrap_or_default();
            get_terminal_profile_start_on_user_login(&files)
        }
        Action::GetAppCertDlls => get_app_cert_dlls(hives),
        Action::GetAppPaths => get_app_paths(hives),
        Action::GetServiceDlls => get_service_dlls(hives),
        Action::GetGpExtensionDlls => get_gp_extension_dlls(hives),
        Action::GetWinlogonMpNotify => get_winlogon_mpnotify(hives),
        Action::GetChmHelperDll => get_chm_helper_dll(hives),
        Action::GetStartupPrograms => {
            let files = source.map(get_startup_files).unwrap_or_default();
            get_startup_programs(&files)
        }
        Action::GetScheduledTasks => get_scheduled_tasks(hives, source),
        Action::GetWindowsServices => get_windows_services(hives),
        Action::GetUserInitMprScript => get_user_init_mpr_script(hives),
        Action::GetHhCtrlHijacking => get_hhctrl_hijacking(hives),
        Action::GetAppInitDlls => get_app_init_dlls(hives),
        Action::GetLsaPackages => get_lsa_packages(hives),
        Action::GetBootExecute => get_boot_execute(hives),
        Action::GetActiveSetup => get_active_setup(hives),
        Action::GetScreensaver => get_screensaver(hives),
        Action::GetSilentProcessExit => get_silent_process_exit(hives),
        Action::GetComHijacking => get_com_hijacking(hives),
        Action::GetPrintMonitors => get_print_monitors(hives),
        Action::GetTimeProviders => get_time_providers(hives),
        Action::GetNetshHelperDlls => get_netsh_helper_dlls(hives),
        Action::GetPowerShellProfiles => {
            if let Some(src) = source {
                get_powershell_profiles(src)
            } else {
                Vec::new()
            }
        }
        Action::GetLinuxPersistence | Action::All => Vec::new(),
    }
}

fn process_target_directory(
    path: &Path,
    action: &Action,
    silent: bool,
    all_events: &mut Vec<event::Event>,
) {
    let raw_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let hostname = if raw_name.starts_with("uac-") || raw_name.starts_with("uac_results_") {
        let stripped = raw_name
            .trim_start_matches("uac-")
            .trim_start_matches("uac_results_");
        if let Some(pos) = stripped.find("-linux") {
            stripped[..pos].to_string()
        } else if let Some(pos) = stripped.find(".tar") {
            stripped[..pos].to_string()
        } else {
            stripped.to_string()
        }
    } else {
        raw_name
    };

    // 1. Check if Linux system / triage
    if parsers::linux::is_linux_target(path) {
        if *action == Action::All || *action == Action::GetLinuxPersistence {
            if !silent {
                println!("🐧 Detected Linux target [{}]: {}", hostname, path.display());
            }
            let linux_events = parsers::linux::process_linux_target(path, &hostname);
            all_events.extend(linux_events);
        }
        return;
    }

    // 2. Process Windows artifacts ONLY if not Linux
    if *action != Action::GetLinuxPersistence {
        let hives = get_hives(path);
        if hives.is_empty() && !path.join("Windows").exists() && !path.join("windows").exists() {
            return;
        }

        if !silent {
            println!("🪟 Detected Windows target [{}]: {}", hostname, path.display());
        }

        let persistences = if *action == Action::All {
            run_all(&hives, path)
        } else {
            execute_action(action, &hives, Some(path))
        };

        for p in &persistences {
            all_events.push(persistence_to_event(p, &hostname));
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Collect evidence directories and files (supports both standard and legacy CLI flags)
    let mut raw_dirs = args.directory.clone();
    if let Some(ref se) = args.source_evidence {
        raw_dirs.push(se.to_string_lossy().to_string());
    }
    let raw_files = args.file.clone();

    if raw_dirs.is_empty() && raw_files.is_empty() {
        eprintln!("Faramir - Error: At least one directory or file must be provided.");
        eprintln!("Usage examples:");
        eprintln!("  faramir -d /path/to/evidence -o timeline.csv");
        eprintln!("  faramir -f evidence.E01 -o timeline.csv");
        eprintln!("  faramir --source-evidence C:\\mount --csv-output C:\\out all");
        std::process::exit(1);
    }

    // Determine output file path
    let out_file: PathBuf = if let Some(ref o) = args.output {
        if o.is_dir() {
            o.join("faramir.output.csv")
        } else {
            o.clone()
        }
    } else if let Some(ref pfx) = args.csv_output {
        if pfx.is_dir() {
            pfx.join("faramir.output.csv")
        } else {
            pfx.clone()
        }
    } else {
        PathBuf::from("faramir.output.csv")
    };

    if !args.silent {
        println!("⚔️  Faramir v0.2.0 - DFIR Persistence Hunting Tool");
        println!("==================================================");
    }

    let (direct_dirs, direct_files, archives, images) =
        ingest::discover_evidence_targets(
            if raw_dirs.is_empty() { None } else { Some(&raw_dirs) },
            if raw_files.is_empty() { None } else { Some(&raw_files) },
        );

    let mut all_events: Vec<event::Event> = Vec::new();

    // 1. Process forensic disk images streaming
    if !images.is_empty() {
        if !args.silent {
            println!("💿 Discovered {} forensic disk image(s). Parsing NTFS & VSS...", images.len());
        }
        for (idx, img) in images.iter().enumerate() {
            let unique_id = format!("faramir_img_{}_{}", std::process::id(), idx);
            let staging = std::env::temp_dir().join(unique_id);
            let _ = std::fs::create_dir_all(&staging);

            let img_name = img.file_name().unwrap_or_default().to_string_lossy();
            if !args.silent {
                println!("  [{}/{}] Extracting image: {}", idx + 1, images.len(), img_name);
            }

            if let Ok(extracted) = ingest::image::unpack_disk_image(img, &staging, args.silent) {
                process_target_directory(&extracted, &args.action, args.silent, &mut all_events);
            }
            let _ = std::fs::remove_dir_all(&staging);
        }
    }

    // 2. Process forensic archives streaming
    if !archives.is_empty() {
        if !args.silent {
            println!("📦 Discovered {} forensic archive(s) / triage packages...", archives.len());
        }
        for (idx, archive) in archives.iter().enumerate() {
            let unique_id = format!("faramir_arc_{}_{}", std::process::id(), idx);
            let staging = std::env::temp_dir().join(unique_id);
            let _ = std::fs::create_dir_all(&staging);

            let arc_name = archive.file_name().unwrap_or_default().to_string_lossy();
            if !args.silent {
                println!("  [{}/{}] Unpacking triage: {}", idx + 1, archives.len(), arc_name);
            }

            if let Ok(extracted_dirs) = ingest::archive::unpack_archive_recursive(archive, &staging, args.silent) {
                for dir in extracted_dirs {
                    process_target_directory(&dir, &args.action, args.silent, &mut all_events);
                }
            }
            let _ = std::fs::remove_dir_all(&staging);
        }
    }

    // 3. Process direct directories
    for dir in direct_dirs {
        process_target_directory(&dir, &args.action, args.silent, &mut all_events);
    }

    // 4. Process direct individual files
    for file in direct_files {
        let path = file.as_path();
        let hostname = "SingleFile";

        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if fname.ends_with(".service") || fname.contains("cron") || fname.contains("profile") {
            let linux_events = parsers::linux::process_linux_target(path, hostname);
            all_events.extend(linux_events);
        } else {
            // Treat as standalone hive
            let hives = vec![path.to_path_buf()];
            let persistences = if args.action == Action::All {
                run_all(&hives, path.parent().unwrap_or(path))
            } else {
                execute_action(&args.action, &hives, path.parent())
            };

            for p in &persistences {
                all_events.push(persistence_to_event(p, hostname));
            }
        }
    }

    // Sort chronologically
    all_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    if !args.silent {
        println!("📊 Total persistence events collected: {}", all_events.len());
    }

    // Export timeline in unified Masstin/Caarea CSV format
    csv_out::export_timeline(&all_events, &out_file, args.silent)?;

    Ok(())
}
