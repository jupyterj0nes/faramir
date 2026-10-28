use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, ValueEnum};

use faramir::windows::{self, diag, HiveSet, TechniqueId};
use faramir::{carve, csv_out, event, ingest, parsers};

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
    GetDeletedPersistence,
    GetLinuxPersistence,
}

impl Action {
    fn technique(&self) -> Option<TechniqueId> {
        Some(match self {
            Action::GetRun => TechniqueId::Run,
            Action::GetRunOnce => TechniqueId::RunOnce,
            Action::GetRunEx => TechniqueId::RunEx,
            Action::GetRunOnceEx => TechniqueId::RunOnceEx,
            Action::GetImageFileExecutionOptions => TechniqueId::ImageFileExecutionOptions,
            Action::GetNldpDllOverridePath => TechniqueId::NldpDllOverridePath,
            Action::GetAedebug => TechniqueId::AeDebug,
            Action::GetWerFaultHangs => TechniqueId::WerFaultHangs,
            Action::GetCmdAutorun => TechniqueId::CmdAutorun,
            Action::GetExplorerLoad => TechniqueId::ExplorerLoad,
            Action::GetWinlogonUserinit => TechniqueId::WinlogonUserinit,
            Action::GetWinlogonShell => TechniqueId::WinlogonShell,
            Action::GetTerminalProfileStartOnUserLogin => TechniqueId::TerminalProfileStartOnUserLogin,
            Action::GetAppCertDlls => TechniqueId::AppCertDlls,
            Action::GetAppPaths => TechniqueId::AppPaths,
            Action::GetServiceDlls => TechniqueId::ServiceDlls,
            Action::GetGpExtensionDlls => TechniqueId::GpExtensionDlls,
            Action::GetWinlogonMpNotify => TechniqueId::WinlogonMpNotify,
            Action::GetChmHelperDll => TechniqueId::ChmHelperDll,
            Action::GetStartupPrograms => TechniqueId::StartupPrograms,
            Action::GetScheduledTasks => TechniqueId::ScheduledTasks,
            Action::GetWindowsServices => TechniqueId::WindowsServices,
            Action::GetUserInitMprScript => TechniqueId::UserInitMprScript,
            Action::GetHhCtrlHijacking => TechniqueId::HhCtrlHijacking,
            Action::GetAppInitDlls => TechniqueId::AppInitDlls,
            Action::GetLsaPackages => TechniqueId::LsaPackages,
            Action::GetBootExecute => TechniqueId::BootExecute,
            Action::GetActiveSetup => TechniqueId::ActiveSetup,
            Action::GetScreensaver => TechniqueId::Screensaver,
            Action::GetSilentProcessExit => TechniqueId::SilentProcessExit,
            Action::GetComHijacking => TechniqueId::ComHijacking,
            Action::GetPrintMonitors => TechniqueId::PrintMonitors,
            Action::GetTimeProviders => TechniqueId::TimeProviders,
            Action::GetNetshHelperDlls => TechniqueId::NetshHelperDlls,
            Action::GetPowerShellProfiles => TechniqueId::PowerShellProfiles,
            Action::GetDeletedPersistence => TechniqueId::DeletedRegistry,
            Action::All | Action::GetLinuxPersistence => return None,
        })
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "faramir",
    version = "0.3.0",
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

    /// Also print informational diagnostics (companion files skipped, logs matched remotely, ...)
    #[arg(long = "verbose")]
    verbose: bool,

    /// Also carve registry hives out of the raw bytes of every disk image, and
    /// of plain files given with -f that are not hives (pagefile, memory dump,
    /// unallocated-space dump). Reads the whole image; off by default. Every
    /// finding it produces is tagged "carved".
    #[arg(long = "carve")]
    carve: bool,

    /// Action to perform
    #[arg(default_value = "all")]
    action: Action,
}

fn run_windows(set: &mut HiveSet, action: &Action, source: &Path) -> Vec<windows::Persistence> {
    match action.technique() {
        None => windows::run_all(set, source),
        Some(id) => windows::run_technique(id, set, Some(source)),
    }
}

/// Analyse one evidence directory. Returns the Windows findings so a carving
/// pass over the same image can fold what the live registry already shows.
fn process_target_directory(
    path: &Path,
    action: &Action,
    silent: bool,
    all_events: &mut Vec<event::Event>,
    hostname_override: Option<&str>,
) -> Vec<windows::Persistence> {
    let raw_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let hostname = if let Some(h) = hostname_override {
        h.to_string()
    } else if raw_name.starts_with("uac-") || raw_name.starts_with("uac_results_") {
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

    // 0. Linux volumes staged out of a disk image: each one is its own host
    let linux_volumes: Vec<PathBuf> = std::fs::read_dir(path)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir() && p.file_name().map(|n| ingest::linux_image::is_linux_volume_dir(&n.to_string_lossy())).unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    if !linux_volumes.is_empty() {
        if *action == Action::All || *action == Action::GetLinuxPersistence {
            for vol in &linux_volumes {
                let host = std::fs::read_to_string(vol.join("etc").join("hostname"))
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| hostname.clone());
                if !silent {
                    println!("🐧 Detected Linux volume [{}]: {}", host, vol.display());
                }
                all_events.extend(parsers::linux::process_linux_target(vol, &host));
            }
        }
        if *action == Action::GetLinuxPersistence {
            return Vec::new();
        }
        // Windows volumes of the same image, if any, are handled below;
        // the generic Linux detection must not re-read the volumes just done.
        let mut set = HiveSet::discover(path);
        if set.is_empty() {
            return Vec::new();
        }
        if !silent {
            println!("🪟 Detected Windows target [{}]: {} ({} hive(s))", hostname, path.display(), set.len());
        }
        let persistences = windows::fold_vss_findings(run_windows(&mut set, action, path));
        for p in &persistences {
            all_events.push(windows::persistence_to_event(p, &hostname));
        }
        return persistences;
    }

    // 1. Linux system / triage
    if parsers::linux::is_linux_target(path) {
        if *action == Action::All || *action == Action::GetLinuxPersistence {
            if !silent {
                println!("🐧 Detected Linux target [{}]: {}", hostname, path.display());
            }
            let linux_events = parsers::linux::process_linux_target(path, &hostname);
            all_events.extend(linux_events);
        }
        return Vec::new();
    }

    // 2. Windows artifacts
    if *action != Action::GetLinuxPersistence {
        let mut set = HiveSet::discover(path);
        if set.is_empty() && !path.join("Windows").exists() && !path.join("windows").exists() {
            return Vec::new();
        }
        if !silent {
            println!("🪟 Detected Windows target [{}]: {} ({} hive(s))", hostname, path.display(), set.len());
        }
        let persistences = windows::fold_vss_findings(run_windows(&mut set, action, path));
        let removed = persistences.iter().filter(|p| p.source.starts_with("vss:")).count();
        if removed > 0 && !silent {
            println!("🕰️  {} persistence item(s) exist only in Volume Shadow Copies (removed from the live volume)", removed);
        }
        for p in &persistences {
            all_events.push(windows::persistence_to_event(p, &hostname));
        }
        return persistences;
    }
    Vec::new()
}

#[allow(clippy::too_many_arguments)]
/// `--carve`: scan the raw bytes of `source` (image or plain file) for hives,
/// run the techniques on what comes out and add the findings tagged `carved`.
/// `extracted` is the staging folder of the same image, so copies identical
/// to the hives already analysed are skipped; `live` are that run's findings.
fn carve_and_process(
    source: &Path,
    staging: &Path,
    extracted: Option<&Path>,
    live: &[windows::Persistence],
    hostname: &str,
    action: &Action,
    silent: bool,
    all_events: &mut Vec<event::Event>,
) {
    if *action == Action::GetLinuxPersistence {
        return;
    }
    if !silent {
        println!("🔪 Carving registry hives from raw bytes of {}", source.display());
    }
    let known = extracted.map(carve::fingerprints_under).unwrap_or_default();
    let carved_dir = staging.join("carved");
    let report = carve::carve_path(source, &carved_dir, &known);
    if !silent {
        println!("  └─ {}", carve::summary_line(&report));
    }
    if report.hives.is_empty() {
        return;
    }
    let mut set = HiveSet::from_paths(&report.hive_paths(), &carved_dir);
    if set.is_empty() {
        return;
    }
    let findings = run_windows(&mut set, action, &carved_dir);
    let (tagged, fold) = carve::tag_and_fold(live, findings, &report.hives);
    if !silent {
        println!(
            "🔪 {} carved persistence item(s) kept ({} already present live, {} repeated across carved hives)",
            fold.kept, fold.folded_into_live, fold.folded_into_carved
        );
    }
    for p in &tagged {
        all_events.push(windows::persistence_to_event(p, hostname));
    }
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown".to_string());
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("\x1b[35m[PANIC] {msg} ({loc}) -- caught, continuing\x1b[0m");
    }));
}

fn main() -> Result<()> {
    let args = Args::parse();
    install_panic_hook();
    diag::set_quiet(args.silent);
    diag::set_verbose(args.verbose);

    let mut raw_dirs = args.directory.clone();
    if let Some(ref se) = args.source_evidence {
        raw_dirs.push(se.to_string_lossy().to_string());
    }
    let raw_files = args.file.clone();

    if raw_dirs.is_empty() && raw_files.is_empty() {
        eprintln!("{}", faramir::errors::FaramirError::CliNoTarget("at least one directory or file must be provided".into()));
        eprintln!("Usage examples:");
        eprintln!("  faramir -d /path/to/evidence -o timeline.csv");
        eprintln!("  faramir -f evidence.E01 -o timeline.csv");
        eprintln!("  faramir --source-evidence C:\\mount --csv-output C:\\out all");
        std::process::exit(1);
    }

    let out_file: PathBuf = if let Some(ref o) = args.output {
        if o.is_dir() { o.join("faramir.output.csv") } else { o.clone() }
    } else if let Some(ref pfx) = args.csv_output {
        if pfx.is_dir() { pfx.join("faramir.output.csv") } else { pfx.clone() }
    } else {
        PathBuf::from("faramir.output.csv")
    };

    if !args.silent {
        println!("⚔️  Faramir v0.3.0 - DFIR Persistence Hunting Tool");
        println!("==================================================");
    }

    let (direct_dirs, direct_files, archives, images) = ingest::discover_evidence_targets(
        if raw_dirs.is_empty() { None } else { Some(&raw_dirs) },
        if raw_files.is_empty() { None } else { Some(&raw_files) },
    );

    let mut all_events: Vec<event::Event> = Vec::new();

    // 1. Forensic disk images
    if !images.is_empty() {
        if !args.silent {
            println!("💿 Discovered {} forensic disk image(s). Parsing NTFS & VSS...", images.len());
        }
        for (idx, img) in images.iter().enumerate() {
            let staging = std::env::temp_dir().join(format!("faramir_img_{}_{}", std::process::id(), idx));
            let _ = std::fs::create_dir_all(&staging);
            if !args.silent {
                println!("  [{}/{}] Extracting image: {}", idx + 1, images.len(), img.file_name().unwrap_or_default().to_string_lossy());
            }
            let (extracted, live) = match ingest::image::unpack_disk_image(img, &staging, args.silent) {
                Ok(extracted) => {
                    let live = process_target_directory(&extracted, &args.action, args.silent, &mut all_events, None);
                    (Some(extracted), live)
                }
                Err(e) => {
                    diag::record(faramir::errors::FaramirError::ImageOpenFailed(format!("{}: {e}", img.display())));
                    (None, Vec::new())
                }
            };
            if args.carve {
                let hostname = img.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "Unknown".to_string());
                carve_and_process(img, &staging, extracted.as_deref(), &live, &hostname, &args.action, args.silent, &mut all_events);
            }
            let _ = std::fs::remove_dir_all(&staging);
        }
    }

    // 2. Forensic archives / triages
    if !archives.is_empty() {
        if !args.silent {
            println!("📦 Discovered {} forensic archive(s) / triage packages...", archives.len());
        }
        for (idx, archive) in archives.iter().enumerate() {
            let staging = std::env::temp_dir().join(format!("faramir_arc_{}_{}", std::process::id(), idx));
            let _ = std::fs::create_dir_all(&staging);
            let triage = ingest::archive::inspect_triage_archive(archive);
            let triage_host = triage.as_ref().and_then(|t| t.hostname.clone());
            if !args.silent {
                let label = triage
                    .as_ref()
                    .map(|t| format!(" [{}{}]", t.kind.label(), triage_host.as_deref().map(|h| format!(", host {h}")).unwrap_or_default()))
                    .unwrap_or_default();
                println!("  [{}/{}] Unpacking triage: {}{}", idx + 1, archives.len(), archive.file_name().unwrap_or_default().to_string_lossy(), label);
            }
            match ingest::archive::unpack_archive_recursive(archive, &staging, args.silent) {
                Ok(extracted_dirs) => {
                    for dir in extracted_dirs {
                        process_target_directory(&dir, &args.action, args.silent, &mut all_events, triage_host.as_deref());
                    }
                }
                Err(e) => {
                    diag::record(faramir::errors::FaramirError::ArchiveUnpackError(format!("{}: {e}", archive.display())));
                }
            }
            let _ = std::fs::remove_dir_all(&staging);
        }
    }

    // 3. Direct directories
    for dir in direct_dirs {
        process_target_directory(&dir, &args.action, args.silent, &mut all_events, None);
    }

    // 4. Direct individual files
    let mut carved_any_file = false;
    for (idx, file) in direct_files.iter().enumerate() {
        let path = file.as_path();
        let hostname = "SingleFile";
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if fname.ends_with(".service") || fname.contains("cron") || fname.contains("profile") {
            let linux_events = parsers::linux::process_linux_target(path, hostname);
            all_events.extend(linux_events);
        } else if args.carve && !faramir::carve::hive::starts_with_regf(path) {
            // not a hive: treat it as a blob to carve (pagefile, memory dump, slack dump)
            carved_any_file = true;
            let staging = std::env::temp_dir().join(format!("faramir_carve_{}_{}", std::process::id(), idx));
            let _ = std::fs::create_dir_all(&staging);
            let host = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| hostname.to_string());
            carve_and_process(path, &staging, None, &[], &host, &args.action, args.silent, &mut all_events);
            let _ = std::fs::remove_dir_all(&staging);
        } else {
            let parent = path.parent().unwrap_or(path).to_path_buf();
            let mut set = HiveSet::from_paths(&[path.to_path_buf()], &parent);
            if set.is_empty() {
                continue;
            }
            let persistences = run_windows(&mut set, &args.action, &parent);
            for p in &persistences {
                all_events.push(windows::persistence_to_event(p, hostname));
            }
        }
    }
    if args.carve && images.is_empty() && !carved_any_file {
        diag::record(faramir::errors::FaramirError::CarveNoTarget(
            "carving reads disk images (-f image.E01/.vmdk/.vhdx/.raw) or plain files given with -f; directories and triage archives are not carved".into(),
        ));
    }

    all_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let summary = diag::summary();
    if !args.silent {
        println!("📊 Total persistence events collected: {}", all_events.len());
        println!(
            "🩺 Diagnostics: {} error(s), {} warning(s), {} info(s)",
            summary.errors, summary.warnings, summary.infos
        );
    }

    csv_out::export_timeline(&all_events, &out_file, args.silent)?;
    Ok(())
}
