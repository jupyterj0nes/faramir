//! A synthetic Cortex XDR offline-collector package, laid out the way real
//! collections are: `offline_collector_output_<HOST>_<date>_<time>.zip` →
//! `output/manifest.json`, `output/cortex-xdr-payload.log` and one
//! `output/<module>-collection/script_output.zip` per module, each file inside
//! its own `entry_<N>_<M>/` folder. Hives and their transaction logs therefore
//! live in different folders and several `NTUSER.DAT` / `NTUSER.DAT.LOG1`
//! share the same file name: only the embedded hive name can pair them.
mod common;

use common::*;
use faramir::ingest::archive::{inspect_triage_archive, nested_extraction_dir, unpack_archive_recursive};
use faramir::ingest::triage::TriageType;
use faramir::windows::diag;
use faramir::windows::hives::HiveKind;
use faramir::windows::txlog::clear_log_index;
use faramir::windows::{run_all, HiveSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::write::FileOptions;
use zip::ZipWriter;

const HOST: &str = "TESTHOST01";
const RUN_HKLM: &str = r"Microsoft\Windows\CurrentVersion\Run";
const RUN_HKCU: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut w = ZipWriter::new(&mut cursor);
        let opts = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    cursor.into_inner()
}

struct Package {
    zip_path: PathBuf,
}

/// Dirty hives whose logs add the marker values below.
fn build_package(dir: &TempDir, logs_in_same_entry: bool, include_logs: bool) -> Package {
    // SYSTEM: dirty, LOG1 adds an evil service
    let sys_base = {
        let mut b = HiveBuilder::system();
        b.dword("Select", "Current", 1).key("ControlSet001");
        b
    };
    let mut sys_step = sys_base.clone();
    sys_step
        .sz(r"ControlSet001\Services\EvilSvc", "ImagePath", r"C:\Windows\Temp\evilsvc.exe")
        .sz(r"ControlSet001\Services\EvilSvc", "DisplayName", "EvilSvc");
    let sys = build_dirty(&sys_base, &[&sys_step], 7, false);

    // SOFTWARE: dirty, LOG1 + LOG2 chain adds Run + Active Setup
    let sw_base = HiveBuilder::software();
    let mut sw_s1 = sw_base.clone();
    sw_s1.sz(RUN_HKLM, "Updater", r"C:\ProgramData\updater.exe");
    let mut sw_s2 = sw_s1.clone();
    sw_s2.sz(r"Microsoft\Active Setup\Installed Components\{EVIL}", "StubPath", r"C:\ProgramData\stub.exe");
    let sw = build_dirty(&sw_base, &[&sw_s1, &sw_s2], 11, true);

    // Two users, identical file names, different embedded names and markers
    let bob = {
        let base = HiveBuilder::ntuser("bob");
        let mut step = base.clone();
        step.sz(RUN_HKCU, "BobRun", r"C:\Users\bob\bob.exe");
        build_dirty(&base, &[&step], 3, false)
    };
    let alice = {
        let base = HiveBuilder::ntuser("alice");
        let mut step = base.clone();
        step.sz(RUN_HKCU, "AliceRun", r"C:\Users\alice\alice.exe");
        build_dirty(&base, &[&step], 9, false)
    };

    // UsrClass: clean, COM hijack
    let mut uc = HiveBuilder::usrclass("bob");
    uc.sz(r"CLSID\{COMEVIL}\InprocServer32", "", r"C:\Users\bob\com.dll");
    let uc_bytes = uc.build();

    let mut reg: Vec<(String, Vec<u8>)> = Vec::new();
    if logs_in_same_entry {
        reg.push(("entry_40_0/SYSTEM".into(), sys.primary.clone()));
        if include_logs {
            reg.push(("entry_40_0/SYSTEM.LOG1".into(), sys.log1.clone()));
        }
        reg.push(("entry_41_0/SOFTWARE".into(), sw.primary.clone()));
        if include_logs {
            reg.push(("entry_41_0/SOFTWARE.LOG1".into(), sw.log1.clone()));
            reg.push(("entry_41_0/SOFTWARE.LOG2".into(), sw.log2.clone().unwrap()));
        }
        reg.push(("entry_50_0/NTUSER.DAT".into(), bob.primary.clone()));
        reg.push(("entry_51_0/NTUSER.DAT".into(), alice.primary.clone()));
        if include_logs {
            reg.push(("entry_50_0/NTUSER.DAT.LOG1".into(), bob.log1.clone()));
            reg.push(("entry_51_0/NTUSER.DAT.LOG1".into(), alice.log1.clone()));
        }
    } else {
        reg.push(("entry_40_0/SYSTEM".into(), sys.primary.clone()));
        if include_logs {
            reg.push(("entry_40_1/SYSTEM.LOG1".into(), sys.log1.clone()));
        }
        reg.push(("entry_77_0/SOFTWARE".into(), sw.primary.clone()));
        if include_logs {
            reg.push(("entry_78_0/SOFTWARE.LOG1".into(), sw.log1.clone()));
            reg.push(("entry_79_0/SOFTWARE.LOG2".into(), sw.log2.clone().unwrap()));
        }
        // logs deliberately NOT adjacent to their hive, alice's log listed before bob's
        reg.push(("entry_50_0/NTUSER.DAT".into(), bob.primary.clone()));
        reg.push(("entry_52_0/NTUSER.DAT".into(), alice.primary.clone()));
        if include_logs {
            reg.push(("entry_51_0/NTUSER.DAT.LOG1".into(), alice.log1.clone()));
            reg.push(("entry_53_0/NTUSER.DAT.LOG1".into(), bob.log1.clone()));
        }
    }
    reg.push(("entry_60_0/UsrClass.dat".into(), uc_bytes));
    reg.push(("entry_60_1/UsrClass.dat{guid}.TM.blf".into(), b"blf".to_vec()));
    let reg_refs: Vec<(&str, &[u8])> = reg.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let registry_zip = zip_bytes(&reg_refs);

    let evtx = {
        let mut v = b"ElfFile\0".to_vec();
        v.resize(4096, 0);
        v
    };
    let event_zip = zip_bytes(&[("entry_159_0/Security.evtx", &evtx)]);

    let task_xml = br#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>C:\Windows\Temp\task.exe</Command></Exec></Actions></Task>"#;
    let tasks_zip = zip_bytes(&[("entry_9_0/Tasks/EvilTask", task_xml.as_slice())]);

    let manifest = br#"{"version":"1","hostname":"TESTHOST01","modules":["registry_hives-collection","event_log-parsing","scheduled_tasks-collection"]}"#;
    let payload_log = b"2026-10-28 12:00:00 collector started\n2026-10-28 12:00:05 module registry_hives-collection done\n";

    let outer = zip_bytes(&[
        ("output/manifest.json", manifest.as_slice()),
        ("output/cortex-xdr-payload.log", payload_log.as_slice()),
        ("output/registry_hives-collection/script_output.zip", &registry_zip),
        ("output/event_log-parsing/script_output.zip", &event_zip),
        ("output/scheduled_tasks-collection/script_output.zip", &tasks_zip),
    ]);
    let zip_path = dir.write(&format!("offline_collector_output_{HOST}_2026-10-28_12-00-00.zip"), &outer);
    Package { zip_path }
}

fn unpack(dir: &TempDir, pkg: &Package) -> Vec<PathBuf> {
    let staging = dir.mkdir("staging");
    unpack_archive_recursive(&pkg.zip_path, &staging, true).unwrap()
}

// ─── detection & unpacking ───────────────────────────────────────────────────

#[test]
fn package_is_detected_as_cortex_xdr_with_hostname() {
    let d = TempDir::new("xdr_detect");
    let pkg = build_package(&d, false, true);
    let info = inspect_triage_archive(&pkg.zip_path).unwrap();
    assert_eq!(info.kind, TriageType::CortexXdr);
    assert_eq!(info.hostname.as_deref(), Some(HOST));
}

#[test]
fn nested_script_output_zips_are_unpacked_in_place_as_one_root() {
    let d = TempDir::new("xdr_unpack");
    let pkg = build_package(&d, false, true);
    let roots = unpack(&d, &pkg);
    assert_eq!(roots.len(), 1, "one evidence root per package, got {roots:?}");
    let root = &roots[0];
    assert!(root.join("output/manifest.json").exists());
    let reg = root.join("output/registry_hives-collection/script_output_extracted");
    assert!(reg.join("entry_40_0/SYSTEM").exists());
    assert!(reg.join("entry_40_1/SYSTEM.LOG1").exists(), "transaction logs must be extracted");
    assert!(reg.join("entry_78_0/SOFTWARE.LOG1").exists());
    assert!(reg.join("entry_79_0/SOFTWARE.LOG2").exists());
    assert!(reg.join("entry_51_0/NTUSER.DAT.LOG1").exists());
    assert!(reg.join("entry_60_0/UsrClass.dat").exists());
    assert!(!reg.join("entry_60_1/UsrClass.dat{guid}.TM.blf").exists(), "TxR blobs are not extracted");
    assert!(!root.join("output/registry_hives-collection/script_output.zip").exists(), "nested zip removed after expansion");
    assert!(root.join("output/event_log-parsing/script_output_extracted/entry_159_0/Security.evtx").exists());
    assert!(root.join("output/scheduled_tasks-collection/script_output_extracted/entry_9_0/Tasks/EvilTask").exists());
}

#[test]
fn nested_extraction_dir_naming() {
    assert_eq!(nested_extraction_dir(Path::new("a/b/script_output.zip")), PathBuf::from("a/b/script_output_extracted"));
    assert_eq!(nested_extraction_dir(Path::new("x/data.tar.gz")), PathBuf::from("x/data_extracted"));
    assert_eq!(nested_extraction_dir(Path::new("x/u.tgz")), PathBuf::from("x/u_extracted"));
}

// ─── hives & transaction logs across entry folders ───────────────────────────

#[test]
fn every_hive_is_discovered_and_recovered_when_logs_sit_in_other_entries() {
    diag::clear();
    clear_log_index();
    let d = TempDir::new("xdr_recover");
    let pkg = build_package(&d, false, true);
    let root = unpack(&d, &pkg).remove(0);

    let mut set = HiveSet::discover(&root);
    let mut kinds = set.kinds();
    kinds.sort_by_key(|k| k.label());
    assert_eq!(kinds, vec![HiveKind::NtUser, HiveKind::NtUser, HiveKind::Software, HiveKind::System, HiveKind::UsrClass]);
    assert_eq!(set.infos().iter().filter(|i| i.is_dirty()).count(), 4);

    let all = run_all(&mut set, &root);
    let values: Vec<&str> = all.iter().map(|p| p.value.as_str()).collect();
    for expected in [r"C:\ProgramData\updater.exe", r"C:\ProgramData\stub.exe", r"C:\Users\bob\bob.exe", r"C:\Users\alice\alice.exe", r"C:\Users\bob\com.dll", r"C:\Windows\Temp\task.exe", "EvilSvc"] {
        assert!(values.contains(&expected), "missing {expected}: {values:?}");
    }
    assert!(all.iter().any(|p| p.path == r"C:\Windows\Temp\evilsvc.exe"));

    for idx in 0..set.len() {
        let info = set.info(idx).unwrap().clone();
        let rec = set.recovery(idx).expect("every hive opened");
        if info.is_dirty() {
            assert!(rec.logs_applied, "{} not recovered: {:?}", info.path.display(), diag::snapshot());
            assert!(rec.log1.is_some());
        }
        if info.kind == HiveKind::Software {
            assert!(rec.log2.is_some(), "SOFTWARE chain needs LOG2");
        }
    }
    assert_eq!(diag::count("ERR_WIN_HIVE_RECOVERED"), 4);
    assert!(diag::has("ERR_WIN_TX_LOG_REMOTE_MATCH"), "logs matched outside the hive folder");
    assert!(diag::has("ERR_WIN_TX_LOG_HIVE_MISMATCH"), "the other user's NTUSER.DAT.LOG1 must be rejected by header");
    assert!(!diag::has("ERR_WIN_TECH_PANIC"));
    assert!(!diag::has("ERR_WIN_TX_LOG_NOT_FOUND"));
    assert!(!diag::has("ERR_WIN_HIVE_DIRTY"));
}

#[test]
fn users_never_get_each_others_log() {
    diag::clear();
    clear_log_index();
    let d = TempDir::new("xdr_users");
    let pkg = build_package(&d, false, true);
    let root = unpack(&d, &pkg).remove(0);
    let mut set = HiveSet::discover(&root);
    let all = run_all(&mut set, &root);
    let bob = all.iter().find(|p| p.value == r"C:\Users\bob\bob.exe").unwrap();
    let alice = all.iter().find(|p| p.value == r"C:\Users\alice\alice.exe").unwrap();
    assert!(bob.path.ends_with(r"entry_50_0\NTUSER.DAT") || bob.path.ends_with("entry_50_0/NTUSER.DAT"), "{}", bob.path);
    assert!(alice.path.ends_with(r"entry_52_0\NTUSER.DAT") || alice.path.ends_with("entry_52_0/NTUSER.DAT"), "{}", alice.path);
    for idx in 0..set.len() {
        let info = set.info(idx).unwrap();
        if info.kind != HiveKind::NtUser {
            continue;
        }
        let rec = set.recovery(idx).unwrap();
        let log = rec.log1.as_ref().unwrap().to_string_lossy().to_string();
        if info.path.to_string_lossy().contains("entry_50_0") {
            assert!(log.contains("entry_53_0"), "bob's log is entry_53_0, got {log}");
        } else {
            assert!(log.contains("entry_51_0"), "alice's log is entry_51_0, got {log}");
        }
    }
}

#[test]
fn logs_in_the_same_entry_folder_also_work() {
    diag::clear();
    clear_log_index();
    let d = TempDir::new("xdr_same");
    let pkg = build_package(&d, true, true);
    let root = unpack(&d, &pkg).remove(0);
    let mut set = HiveSet::discover(&root);
    let all = run_all(&mut set, &root);
    let values: Vec<&str> = all.iter().map(|p| p.value.as_str()).collect();
    for expected in [r"C:\ProgramData\updater.exe", r"C:\Users\bob\bob.exe", r"C:\Users\alice\alice.exe"] {
        assert!(values.contains(&expected), "missing {expected}: {values:?}");
    }
    assert_eq!(diag::count("ERR_WIN_HIVE_RECOVERED"), 4);
    assert!(!diag::has("ERR_WIN_TX_LOG_REMOTE_MATCH"));
}

#[test]
fn package_without_logs_still_scans_dirty_hives_and_says_so() {
    diag::clear();
    clear_log_index();
    let d = TempDir::new("xdr_nologs");
    let pkg = build_package(&d, false, false);
    let root = unpack(&d, &pkg).remove(0);
    let mut set = HiveSet::discover(&root);
    assert_eq!(set.len(), 5);
    let all = run_all(&mut set, &root);
    let values: Vec<&str> = all.iter().map(|p| p.value.as_str()).collect();
    assert!(values.contains(&r"C:\Users\bob\com.dll"), "clean UsrClass still scanned");
    assert!(values.contains(&r"C:\Windows\Temp\task.exe"));
    assert!(!values.contains(&r"C:\Users\bob\bob.exe"), "marker only exists in the missing log");
    assert_eq!(diag::count("ERR_WIN_TX_LOG_NOT_FOUND"), 4);
    assert_eq!(diag::count("ERR_WIN_HIVE_RECOVERED"), 0);
}

/// Dev utility: `FARAMIR_XDR_SAMPLE_DIR=<dir> cargo test --test test_cortex_xdr_package export_sample_package -- --ignored`
/// writes the synthetic package there so it can be fed to the binary by hand.
#[test]
#[ignore]
fn export_sample_package() {
    let Ok(target) = std::env::var("FARAMIR_XDR_SAMPLE_DIR") else {
        eprintln!("FARAMIR_XDR_SAMPLE_DIR not set, nothing exported");
        return;
    };
    let d = TempDir::new("xdr_export");
    let pkg = build_package(&d, false, true);
    std::fs::create_dir_all(&target).unwrap();
    let dest = Path::new(&target).join(pkg.zip_path.file_name().unwrap());
    std::fs::copy(&pkg.zip_path, &dest).unwrap();
    eprintln!("exported {}", dest.display());
}

// ─── the real binary, end to end ─────────────────────────────────────────────

#[test]
fn cli_processes_the_package_and_names_the_host() {
    let d = TempDir::new("xdr_cli");
    let pkg = build_package(&d, false, true);
    let out = d.join("timeline.csv");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_faramir"))
        .arg("-f")
        .arg(&pkg.zip_path)
        .arg("-o")
        .arg(&out)
        .arg("--verbose")
        .output()
        .expect("run faramir");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Cortex XDR"), "{stdout}");
    assert!(stdout.contains(&format!("host {HOST}")), "{stdout}");
    assert!(stderr.contains("ERR_WIN_HIVE_RECOVERED"), "{stderr}");
    assert!(!stderr.contains("ERR_WIN_TX_LOG_NOT_FOUND"), "{stderr}");
    assert!(!stderr.contains("[PANIC]"), "{stderr}");

    let csv = std::fs::read_to_string(&out).unwrap();
    let rows: Vec<&str> = csv.lines().skip(1).collect();
    for expected in [r"C:\\ProgramData\\updater.exe", r"C:\\Users\\bob\\bob.exe", r"C:\\Users\\alice\\alice.exe", r"C:\\Windows\\Temp\\task.exe", r"C:\\Users\\bob\\com.dll"] {
        let plain = expected.replace("\\\\", "\\");
        let hits = rows.iter().filter(|r| r.contains(&plain) || r.contains(expected)).count();
        assert_eq!(hits, 1, "{plain} should appear exactly once (no duplicate processing): {csv}");
    }
    assert!(rows.iter().all(|r| r.contains(HOST)), "every row must carry the collector hostname: {csv}");
    assert!(csv.contains("windows:persistence:registry_run_key"));
}

#[test]
fn cli_single_technique_on_package() {
    let d = TempDir::new("xdr_cli_run");
    let pkg = build_package(&d, false, true);
    let out = d.join("run.csv");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_faramir"))
        .arg("-f")
        .arg(&pkg.zip_path)
        .arg("-o")
        .arg(&out)
        .arg("--silent")
        .arg("get-run")
        .output()
        .unwrap();
    assert!(output.status.success());
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(csv.contains("updater.exe"));
    assert!(csv.contains("bob.exe"));
    assert!(csv.contains("alice.exe"));
    assert!(!csv.contains("stub.exe"), "active setup is not part of get-run");
    let _ = File::open(&out).unwrap();
}
