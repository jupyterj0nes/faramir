//! Smoke tests for the synthetic hive/log writer and the recovery pipeline.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::{open_hive_path, read_hive_header, HiveKind};
use faramir::windows::techniques::string_value;
use nt_hive2::{Hive, HiveParseMode, SubPath};
use std::fs::File;

fn find_sz(hive: &mut faramir::windows::hives::HiveFile, path: &str, name: &str) -> Option<String> {
    let root = hive.root_key_node().ok()?;
    let key = root.subpath(path, hive).ok()??;
    let key = key.borrow();
    key.values().iter().find(|v| v.name().eq_ignore_ascii_case(name)).and_then(string_value)
}

#[test]
fn builder_hive_is_parsed_by_nt_hive2() {
    let dir = TempDir::new("builder");
    let mut b = HiveBuilder::software();
    b.sz(r"Microsoft\Windows\CurrentVersion\Run", "Updater", r"C:\evil\updater.exe");
    let path = b.write(&dir.join("SOFTWARE"));
    let hive = Hive::new(faramir::windows::hives::HiveSource::File(std::io::BufReader::new(File::open(&path).unwrap())), HiveParseMode::NormalWithBaseBlock).unwrap();
    let mut hive = hive.treat_hive_as_clean();
    assert!(hive.is_checksum_valid().unwrap());
    assert_eq!(find_sz(&mut hive, r"Microsoft\Windows\CurrentVersion\Run", "Updater").as_deref(), Some(r"C:\evil\updater.exe"));
}

#[test]
fn builder_header_round_trips() {
    let dir = TempDir::new("builder_hdr");
    let mut b = HiveBuilder::ntuser("bob");
    b.sequence = 9;
    let path = b.write(&dir.join("NTUSER.DAT"));
    let h = read_hive_header(&path).unwrap();
    assert_eq!(h.primary_sequence, 9);
    assert_eq!(h.secondary_sequence, 9);
    assert!(!h.is_dirty());
    assert!(h.checksum_valid());
    assert!(h.is_primary());
    assert_eq!(h.kind(), HiveKind::NtUser);
    assert_eq!(h.minor_version, 5);
}

#[test]
fn builder_supports_every_value_type() {
    let dir = TempDir::new("builder_types");
    let mut b = HiveBuilder::software();
    b.sz("K", "s", "plain")
        .expand_sz("K", "e", "%SystemRoot%\\x.exe")
        .sz_resident("K", "r", "x")
        .dword("K", "d", 0x1234)
        .multi_sz("K", "m", &["one", "two"])
        .binary("K", "b", &[1, 2, 3, 4, 5]);
    let path = b.write(&dir.join("SOFTWARE"));
    let mut opened = open_hive_path(&path).unwrap();
    let root = opened.hive.root_key_node().unwrap();
    let k = root.subpath("K", &mut opened.hive).unwrap().unwrap();
    let k = k.borrow();
    let get = |n: &str| k.values().iter().find(|v| v.name() == n).unwrap();
    assert_eq!(string_value(get("s")).as_deref(), Some("plain"));
    assert_eq!(string_value(get("e")).as_deref(), Some("%SystemRoot%\\x.exe"));
    assert_eq!(string_value(get("r")).as_deref(), Some("x"), "resident 1-char string must be reconstructed");
    assert_eq!(faramir::windows::techniques::dword_value(get("d")), Some(0x1234));
    assert_eq!(faramir::windows::techniques::multi_string_value(get("m")), vec!["one".to_string(), "two".to_string()]);
    assert!(matches!(get("b").value(), nt_hive2::RegistryValue::RegBinary(v) if v == &[1, 2, 3, 4, 5]));
}

#[test]
fn builder_nested_keys_and_default_value() {
    let dir = TempDir::new("builder_nested");
    let mut b = HiveBuilder::software();
    b.sz(r"Classes\CLSID\{AAAA}\InprocServer32", "", r"C:\evil.dll");
    b.sz(r"Classes\CLSID\{BBBB}\InprocServer32", "", r"C:\good.dll");
    let path = b.write(&dir.join("SOFTWARE"));
    let mut opened = open_hive_path(&path).unwrap();
    let root = opened.hive.root_key_node().unwrap();
    let clsid = root.subpath(r"Classes\CLSID", &mut opened.hive).unwrap().unwrap();
    let clsid = clsid.borrow();
    let subs = clsid.subkeys(&mut opened.hive).unwrap();
    assert_eq!(subs.len(), 2);
    let a = root.subpath(r"Classes\CLSID\{AAAA}\InprocServer32", &mut opened.hive).unwrap().unwrap();
    let a = a.borrow();
    let v = a.values().iter().find(|v| faramir::windows::techniques::is_default_value_name(v.name())).unwrap();
    assert_eq!(string_value(v).as_deref(), Some(r"C:\evil.dll"));
}

#[test]
fn dirty_fixture_is_recovered_from_log1() {
    diag::clear();
    let dir = TempDir::new("dirty_smoke");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(r"Microsoft\Windows\CurrentVersion\Run", "Dropper", r"C:\Temp\d.exe");
    let fx = build_dirty(&base, &[&step], 5, false);
    let hive_path = write_dirty(&dir, "SOFTWARE", &fx);

    let h = read_hive_header(&hive_path).unwrap();
    assert!(h.is_dirty());
    assert_eq!(h.primary_sequence, 6);

    let mut opened = open_hive_path(&hive_path).unwrap();
    assert!(opened.recovery.was_dirty);
    assert!(opened.recovery.logs_applied, "log must be applied: {:?}", diag::snapshot());
    assert_eq!(opened.recovery.log1.as_deref(), Some(dir.join("SOFTWARE.LOG1").as_path()));
    assert_eq!(find_sz(&mut opened.hive, r"Microsoft\Windows\CurrentVersion\Run", "Dropper").as_deref(), Some(r"C:\Temp\d.exe"));
    assert!(diag::has("ERR_WIN_HIVE_RECOVERED"));
}

#[test]
fn dirty_fixture_without_log_keeps_on_disk_state() {
    diag::clear();
    let dir = TempDir::new("dirty_nolog");
    let mut base = HiveBuilder::software();
    base.sz(r"Microsoft\Windows\CurrentVersion\Run", "Old", r"C:\old.exe");
    let mut step = HiveBuilder::software();
    step.sz(r"Microsoft\Windows\CurrentVersion\Run", "Old", r"C:\old.exe");
    step.sz(r"Microsoft\Windows\CurrentVersion\Run", "New", r"C:\new.exe");
    let fx = build_dirty(&base, &[&step], 5, false);
    let hive_path = dir.write("SOFTWARE", &fx.primary);

    let mut opened = open_hive_path(&hive_path).unwrap();
    assert!(opened.recovery.was_dirty);
    assert!(!opened.recovery.logs_applied);
    assert!(diag::has("ERR_WIN_TX_LOG_NOT_FOUND"));
    assert_eq!(find_sz(&mut opened.hive, r"Microsoft\Windows\CurrentVersion\Run", "Old").as_deref(), Some(r"C:\old.exe"));
    assert_eq!(find_sz(&mut opened.hive, r"Microsoft\Windows\CurrentVersion\Run", "New"), None);
}

#[test]
fn dirty_fixture_chain_across_log1_and_log2() {
    diag::clear();
    let dir = TempDir::new("dirty_chain");
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(r"Microsoft\Windows\CurrentVersion\Run", "A", r"C:\a.exe");
    let mut s2 = HiveBuilder::software();
    s2.sz(r"Microsoft\Windows\CurrentVersion\Run", "A", r"C:\a.exe");
    s2.sz(r"Microsoft\Windows\CurrentVersion\Run", "B", r"C:\b.exe");
    let fx = build_dirty(&base, &[&s1, &s2], 10, true);
    let hive_path = write_dirty(&dir, "SOFTWARE", &fx);

    let mut opened = open_hive_path(&hive_path).unwrap();
    assert!(opened.recovery.logs_applied, "{:?}", diag::snapshot());
    assert!(opened.recovery.log1.is_some());
    assert!(opened.recovery.log2.is_some());
    assert_eq!(find_sz(&mut opened.hive, r"Microsoft\Windows\CurrentVersion\Run", "B").as_deref(), Some(r"C:\b.exe"));
}

#[test]
fn real_windows_dirty_hive_fixture_is_recovered() {
    diag::clear();
    let dir = TempDir::new("real_dirty");
    for name in ["NewDirtyHive", "NewDirtyHive.LOG1", "NewDirtyHive.LOG2"] {
        std::fs::copy(fixture(&format!("dirty_hive/{name}")), dir.join(name)).unwrap();
    }
    let h = read_hive_header(&dir.join("NewDirtyHive")).unwrap();
    assert!(h.is_dirty());
    assert_eq!((h.primary_sequence, h.secondary_sequence), (3, 2));

    let mut opened = open_hive_path(&dir.join("NewDirtyHive")).unwrap();
    assert!(opened.recovery.was_dirty);
    assert!(opened.recovery.logs_applied, "{:?}", diag::snapshot());
    assert!(opened.recovery.log2.is_some(), "LOG2 carries the matching entry");
    assert!(opened.hive.is_checksum_valid().unwrap());
    let root = opened.hive.root_key_node().unwrap();
    assert!(!root.name().is_empty());
    assert!(diag::has("ERR_WIN_HIVE_RECOVERED"));
}
