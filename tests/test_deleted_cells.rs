//! Deleted keys and values recovered from free hive cells.
mod common;

use common::*;
use faramir::windows::deleted::*;
use faramir::windows::hives::{classify_hive, HiveKind};
use faramir::windows::{diag, persistence_to_event, run_all, run_technique, HiveSet, Persistence, TechniqueId};
use std::path::PathBuf;

const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

fn scan_builder(d: &TempDir, name: &str, b: &HiveBuilder) -> (DeletedScan, PathBuf) {
    let p = b.write(&d.join(name));
    (scan_path(&p).unwrap(), p)
}

fn findings(d: &TempDir, name: &str, b: &HiveBuilder) -> Vec<Persistence> {
    let p = b.write(&d.join(name));
    let mut set = HiveSet::from_paths(&[p], &d.path);
    diag::clear();
    run_technique(TechniqueId::DeletedRegistry, &mut set, None)
}

// ─── raw scan ────────────────────────────────────────────────────────────────

#[test]
fn clean_hive_has_no_deleted_cells() {
    let d = TempDir::new("del_clean");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "Live", r"C:\live.exe");
    let (scan, _) = scan_builder(&d, "SOFTWARE", &b);
    assert!(scan.deleted_keys.is_empty());
    assert!(scan.orphan_values.is_empty());
    assert!(scan.bins >= 1);
    assert!(scan.live_keys >= 5, "root + 4 path components, got {}", scan.live_keys);
    assert!(scan.cells > scan.live_keys);
}

#[test]
fn deleted_value_becomes_orphan_vk_with_its_data() {
    let d = TempDir::new("del_value");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "Keep", r"C:\keep.exe").sz(RUN, "Gone", r"C:\gone.exe").delete_value(RUN, "Gone");
    let (scan, _) = scan_builder(&d, "SOFTWARE", &b);
    assert!(scan.deleted_keys.is_empty());
    assert_eq!(scan.orphan_values.len(), 1);
    let v = &scan.orphan_values[0];
    assert_eq!(v.name, "Gone");
    assert_eq!(v.data.as_deref(), Some(r"C:\gone.exe"));
    assert!(!v.allocated);
    assert_eq!(v.data_type, 1);
}

#[test]
fn deleted_key_is_recovered_with_path_and_values() {
    let d = TempDir::new("del_key");
    let mut b = HiveBuilder::system();
    b.dword("Select", "Current", 1)
        .sz(r"ControlSet001\Services\EvilSvc", "ImagePath", r"C:\Windows\Temp\evil.exe")
        .sz(r"ControlSet001\Services\EvilSvc", "DisplayName", "Evil")
        .dword(r"ControlSet001\Services\EvilSvc", "Start", 2)
        .sz(r"ControlSet001\Services\GoodSvc", "ImagePath", r"C:\good.exe")
        .delete_key(r"ControlSet001\Services\EvilSvc");
    let (scan, _) = scan_builder(&d, "SYSTEM", &b);
    assert_eq!(scan.deleted_keys.len(), 1);
    let dk = &scan.deleted_keys[0];
    assert_eq!(dk.path, r"ControlSet001\Services\EvilSvc");
    assert_eq!(dk.key.name, "EvilSvc");
    assert!(!dk.key.allocated);
    let names: Vec<&str> = dk.values.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, vec!["ImagePath", "DisplayName", "Start"]);
    assert_eq!(dk.values[0].data.as_deref(), Some(r"C:\Windows\Temp\evil.exe"));
    assert_eq!(dk.values[2].data, None, "DWORD has no string data");
    assert!(scan.orphan_values.is_empty(), "values of a deleted key are not orphans");
}

#[test]
fn deleted_subtree_resolves_every_level() {
    let d = TempDir::new("del_tree");
    let mut b = HiveBuilder::software();
    b.sz(r"Microsoft\Active Setup\Installed Components\{EVIL}", "StubPath", r"C:\stub.exe")
        .delete_key(r"Microsoft\Active Setup");
    let (scan, _) = scan_builder(&d, "SOFTWARE", &b);
    let paths: Vec<&str> = scan.deleted_keys.iter().map(|k| k.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![r"Microsoft\Active Setup", r"Microsoft\Active Setup\Installed Components", r"Microsoft\Active Setup\Installed Components\{EVIL}"]
    );
}

#[test]
fn garbage_free_cells_do_not_break_the_scan() {
    let d = TempDir::new("del_garbage");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "Live", r"C:\live.exe").deleted_sz(RUN, "Gone", r"C:\gone.exe");
    let mut bytes = b.build();
    // corrupt a chunk of the free space at the end of the bin with "nk"/"vk" magics and huge counts
    let len = bytes.len();
    let tail = &mut bytes[len - 512..];
    for i in (0..tail.len()).step_by(16) {
        tail[i..i + 4].copy_from_slice(&0x7FFF_FFF8u32.to_le_bytes()); // absurd positive cell size
        tail[i + 4..i + 6].copy_from_slice(if i % 32 == 0 { b"nk" } else { b"vk" });
        tail[i + 6..i + 16].copy_from_slice(&[0xEE; 10]);
    }
    let p = d.write("SOFTWARE", &bytes);
    let scan = scan_path(&p).unwrap();
    assert_eq!(scan.orphan_values.len(), 1);
    assert_eq!(scan.orphan_values[0].data.as_deref(), Some(r"C:\gone.exe"));
}

#[test]
fn scan_rejects_non_hive_bytes() {
    assert_eq!(HiveImage::new(vec![0u8; 100]).err().map(|e| e.code()), Some("ERR_WIN_HIVE_TRUNCATED"));
    assert_eq!(HiveImage::new(vec![0u8; 8192]).err().map(|e| e.code()), Some("ERR_WIN_HIVE_SIGNATURE"));
}

#[test]
fn real_windows_hive_scans_without_errors() {
    diag::clear();
    let d = TempDir::new("del_real");
    for name in ["NewDirtyHive", "NewDirtyHive.LOG1", "NewDirtyHive.LOG2"] {
        std::fs::copy(fixture(&format!("dirty_hive/{name}")), d.join(name)).unwrap();
    }
    let scan = scan_path(&d.join("NewDirtyHive")).unwrap();
    assert!(scan.bins >= 1);
    assert!(scan.live_keys >= 1);
    assert!(!diag::has("ERR_WIN_TECH_PANIC"));
}

// ─── classification ──────────────────────────────────────────────────────────

#[test]
fn classify_software_paths() {
    assert_eq!(classify_deleted_path(RUN, HiveKind::Software).map(|x| x.0), Some(TechniqueId::Run));
    assert_eq!(classify_deleted_path(r"Microsoft\Windows\CurrentVersion\RunOnce", HiveKind::Software).map(|x| x.0), Some(TechniqueId::RunOnce));
    assert_eq!(
        classify_deleted_path(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", HiveKind::Software).map(|x| x.0),
        Some(TechniqueId::ImageFileExecutionOptions)
    );
    assert_eq!(classify_deleted_path(r"Wow6432Node\Microsoft\Active Setup\Installed Components\{X}", HiveKind::Software).map(|x| x.0), Some(TechniqueId::ActiveSetup));
    assert_eq!(classify_deleted_path(r"Microsoft\Office\16.0", HiveKind::Software), None);
}

#[test]
fn classify_user_paths_use_hkcu_roots() {
    assert_eq!(classify_deleted_path(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", HiveKind::NtUser), Some((TechniqueId::Run, "User")));
    assert_eq!(classify_deleted_path(r"Control Panel\Desktop", HiveKind::NtUser).map(|x| x.0), Some(TechniqueId::Screensaver));
    assert_eq!(classify_deleted_path(r"Software\Classes\CLSID\{X}\InprocServer32", HiveKind::NtUser).map(|x| x.0), Some(TechniqueId::ComHijacking));
    assert_eq!(classify_deleted_path(RUN, HiveKind::NtUser), None, "HKLM layout does not exist in NTUSER");
}

#[test]
fn classify_system_paths_strip_control_set() {
    assert_eq!(classify_deleted_path(r"ControlSet001\Services\EvilSvc", HiveKind::System), Some((TechniqueId::WindowsServices, "System")));
    assert_eq!(classify_deleted_path(r"ControlSet002\Services\W32Time\TimeProviders\Evil", HiveKind::System).map(|x| x.0), Some(TechniqueId::TimeProviders));
    assert_eq!(classify_deleted_path(r"ControlSet001\Control\Print\Monitors\Evil", HiveKind::System).map(|x| x.0), Some(TechniqueId::PrintMonitors));
    assert_eq!(classify_deleted_path(r"ControlSet001\Control\Lsa", HiveKind::System).map(|x| x.0), Some(TechniqueId::LsaPackages));
    assert_eq!(classify_deleted_path(r"ControlSet001\Control\Session Manager\AppCertDlls", HiveKind::System).map(|x| x.0), Some(TechniqueId::AppCertDlls));
    assert_eq!(classify_deleted_path(r"ControlSet001\Control\Session Manager", HiveKind::System).map(|x| x.0), Some(TechniqueId::BootExecute));
    assert_eq!(classify_deleted_path(r"ControlSet001\Enum\PCI", HiveKind::System), None);
    assert_eq!(classify_deleted_path(r"Setup", HiveKind::System), None);
}

#[test]
fn classify_broken_chain_prefix_is_tolerated() {
    assert_eq!(classify_deleted_path(&format!("?\\{RUN}"), HiveKind::Software).map(|x| x.0), Some(TechniqueId::Run));
}

#[test]
fn classify_most_specific_root_wins() {
    assert_eq!(classify_deleted_path(r"Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{X}", HiveKind::Software).map(|x| x.0), Some(TechniqueId::GpExtensionDlls));
}

// ─── findings ────────────────────────────────────────────────────────────────

#[test]
fn deleted_run_values_in_user_hive_are_reported_with_user_access() {
    let d = TempDir::new("del_user_run");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(&format!(r"SOFTWARE\{RUN}"), "A", r"C:\a.exe").sz(&format!(r"SOFTWARE\{RUN}"), "B", r"C:\b.exe").delete_key(&format!(r"SOFTWARE\{RUN}"));
    let f = findings(&d, "NTUSER.DAT", &nt);
    let mut v: Vec<&str> = f.iter().map(|p| p.value.as_str()).collect();
    v.sort();
    assert_eq!(v, vec![r"C:\a.exe", r"C:\b.exe"]);
    assert!(f.iter().all(|p| p.technique == "Registry Run Key" && p.access_gained == "User" && p.source == SOURCE_DELETED));
    assert!(f[0].path.starts_with("deleted key SOFTWARE\\Microsoft"));
    assert_eq!(f[0].timestamp, "2024-01-17 21:20:00.000");
    let e = persistence_to_event(&f[0], "H");
    assert_eq!(e.artifact, "windows:persistence:deleted:registry_run_key");
}

#[test]
fn deleted_service_is_reported() {
    let d = TempDir::new("del_svc");
    let mut sys = HiveBuilder::system();
    sys.dword("Select", "Current", 1)
        .sz(r"ControlSet001\Services\EvilSvc", "ImagePath", r"C:\evil.exe")
        .delete_key(r"ControlSet001\Services\EvilSvc");
    let f = findings(&d, "SYSTEM", &sys);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].technique, "Windows Service");
    assert_eq!(f[0].value, r"C:\evil.exe");
    assert_eq!(f[0].path, r"deleted key ControlSet001\Services\EvilSvc\ImagePath");
}

#[test]
fn deleted_key_without_string_values_is_reported_by_name() {
    let d = TempDir::new("del_noval");
    let mut sw = HiveBuilder::software();
    sw.dword(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "GlobalFlag", 0x200)
        .delete_key(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe");
    let f = findings(&d, "SOFTWARE", &sw);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].value, "sethc.exe");
    assert_eq!(f[0].technique, "Image file execution options");
}

#[test]
fn orphan_values_only_when_they_look_executable() {
    let d = TempDir::new("del_orphan");
    let mut sw = HiveBuilder::software();
    sw.sz(RUN, "Live", r"C:\live.exe")
        .deleted_sz(RUN, "Dropper", r"C:\Users\Public\d.exe -s")
        .deleted_sz(RUN, "Note", "hello world")
        .deleted_sz(r"Microsoft\Foo", "Script", r"wscript.exe C:\t\x.vbs");
    let f = findings(&d, "SOFTWARE", &sw);
    let mut v: Vec<&str> = f.iter().map(|p| p.value.as_str()).collect();
    v.sort();
    assert_eq!(v, vec![r"C:\Users\Public\d.exe -s", r"wscript.exe C:\t\x.vbs"]);
    assert!(f.iter().all(|p| p.technique == "Deleted Registry Persistence" && p.access_gained == "Unknown"));
    assert!(f[0].path.contains("key unknown"));
}

#[test]
fn unrelated_deleted_keys_are_ignored() {
    let d = TempDir::new("del_unrelated");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Office\16.0\Outlook", "Profile", r"C:\x.exe").delete_key(r"Microsoft\Office\16.0\Outlook");
    assert!(findings(&d, "SOFTWARE", &sw).is_empty());
}

#[test]
fn live_findings_are_not_duplicated_by_the_deleted_scan() {
    let d = TempDir::new("del_live");
    let mut sw = HiveBuilder::software();
    sw.sz(RUN, "Live", r"C:\live.exe");
    let f = findings(&d, "SOFTWARE", &sw);
    assert!(f.is_empty());
}

#[test]
fn run_all_includes_deleted_persistence() {
    let d = TempDir::new("del_run_all");
    let mut sw = HiveBuilder::software();
    sw.sz(RUN, "Live", r"C:\live.exe").sz(RUN, "Gone", r"C:\gone.exe").delete_value(RUN, "Gone");
    let p = sw.write(&d.join("SOFTWARE"));
    let info = classify_hive(&p, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::Software);
    let mut set = HiveSet::from_paths(&[p], &d.path);
    let all = run_all(&mut set, &d.path);
    assert!(all.iter().any(|x| x.value == r"C:\live.exe" && x.source.is_empty()));
    assert!(all.iter().any(|x| x.value == r"C:\gone.exe" && x.source == SOURCE_DELETED));
}

#[test]
fn technique_catalogue_includes_deleted_registry() {
    assert_eq!(TechniqueId::ALL.len(), 36);
    assert!(TechniqueId::DeletedRegistry.is_registry_based());
    assert!(TechniqueId::DeletedRegistry.roots().is_empty());
    assert_eq!(TechniqueId::DeletedRegistry.label(), "Deleted Registry Persistence");
}

#[test]
fn deleted_scan_survives_dirty_hive_with_logs() {
    let d = TempDir::new("del_dirty");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Live", r"C:\live.exe").deleted_sz(RUN, "Gone", r"C:\gone.exe");
    let fx = build_dirty(&base, &[&step], 5, false);
    let hive = write_dirty(&d, "SOFTWARE", &fx);
    let scan = scan_path(&hive).unwrap();
    assert_eq!(scan.orphan_values.len(), 1, "scan runs on the replayed state");
}

/// Dev utility: `cargo test --test test_deleted_cells dump_fixture -- --ignored --nocapture`
#[test]
#[ignore]
fn dump_fixture() {
    let d = TempDir::new("del_dump");
    for name in ["NewDirtyHive", "NewDirtyHive.LOG1", "NewDirtyHive.LOG2"] {
        std::fs::copy(fixture(&format!("dirty_hive/{name}")), d.join(name)).unwrap();
    }
    let scan = scan_path(&d.join("NewDirtyHive")).unwrap();
    for k in &scan.deleted_keys {
        eprintln!("deleted key @{:#x} path={} parent={:#x} values={}", k.key.offset, k.path, k.key.parent, k.values.len());
    }
    for v in &scan.orphan_values {
        eprintln!("orphan value @{:#x} {} = {:?}", v.offset, v.name, v.data);
    }
}
