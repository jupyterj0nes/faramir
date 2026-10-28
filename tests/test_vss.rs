//! Volume Shadow Copy folding: snapshot-only persistence is reported as removed.
mod common;

use common::*;
use faramir::ingest::image::{partition_dir_name, VSS_INFO_FILE};
use faramir::windows::vss::*;
use faramir::windows::{fold_vss_findings, persistence_to_event, run_all, HiveSet, Persistence};
use std::path::Path;

fn p(technique: &str, value: &str, path: &str) -> Persistence {
    Persistence {
        timestamp: "2024-01-17 21:20:00.000".into(),
        technique: technique.into(),
        path: path.into(),
        value: value.into(),
        access_gained: "System".into(),
        source: String::new(),
        origin: String::new(),
    }
}

#[test]
fn dir_names() {
    assert_eq!(partition_dir_name(0, None), "partition_0");
    assert_eq!(partition_dir_name(2, Some(7)), "partition_2_vss_7");
    assert_eq!(parse_vss_dir_name("partition_2_vss_7"), Some((2, 7)));
    assert_eq!(parse_vss_dir_name("partition_0"), None);
    assert_eq!(parse_vss_dir_name("partition_x_vss_1"), None);
    assert_eq!(parse_vss_dir_name("vss_1"), None);
}

#[test]
fn sidecar_parsing() {
    let s = parse_vss_info("store=3\npartition=0\ncreated=2026-03-01 10:00:00 UTC\nsequence=42\n", 0, 3);
    assert_eq!(s.store, 3);
    assert_eq!(s.created, "2026-03-01 10:00:00 UTC");
    assert_eq!(s.sequence, 42);
    assert_eq!(s.tag(), "vss:3:2026-03-01 10:00:00 UTC");
    let d = parse_vss_info("", 1, 2);
    assert_eq!(d.created, "unknown");
    assert_eq!((d.partition, d.store), (1, 2));
}

#[test]
fn snapshot_of_reads_sidecar_from_ancestor() {
    let d = TempDir::new("vss_snap");
    d.write(&format!("img/partition_0_vss_2/{VSS_INFO_FILE}"), b"created=2026-02-02 02:02:02 UTC\nsequence=9\n");
    let hive = d.write("img/partition_0_vss_2/config/SOFTWARE", b"x");
    let s = snapshot_of(&hive).unwrap();
    assert_eq!(s.store, 2);
    assert_eq!(s.created, "2026-02-02 02:02:02 UTC");
    assert!(snapshot_of(Path::new("C:/ev/partition_0/config/SOFTWARE")).is_none());
    let no_sidecar = snapshot_of(Path::new("C:/ev/partition_1_vss_4/x/SYSTEM")).unwrap();
    assert_eq!(no_sidecar.created, "unknown");
    assert_eq!(no_sidecar.store, 4);
}

#[test]
fn fold_keeps_live_and_drops_snapshot_duplicates() {
    let out = fold_vss_findings(vec![
        p("Registry Run Key", r"C:\a.exe", r"C:\ev\partition_0\config\SOFTWARE"),
        p("Registry Run Key", r"c:\A.EXE", r"C:\ev\partition_0_vss_1\config\SOFTWARE"),
    ]);
    assert_eq!(out.len(), 1);
    assert!(out[0].source.is_empty());
}

#[test]
fn fold_reports_snapshot_only_findings_as_removed() {
    let out = fold_vss_findings(vec![
        p("Registry Run Key", r"C:\a.exe", r"C:\ev\partition_0\config\SOFTWARE"),
        p("Registry Run Key", r"C:\gone.exe", r"C:\ev\partition_0_vss_1\config\SOFTWARE"),
    ]);
    assert_eq!(out.len(), 2);
    let gone = out.iter().find(|x| x.value == r"C:\gone.exe").unwrap();
    assert!(gone.source.starts_with("vss:1:"));
    assert!(gone.path.starts_with("VSS snapshot created"));
    assert!(gone.path.contains("gone from live volume"));
    let e = persistence_to_event(gone, "H");
    assert_eq!(e.artifact, "windows:persistence:removed_since_vss:registry_run_key");
    let live = persistence_to_event(&out[0], "H");
    assert_eq!(live.artifact, "windows:persistence:registry_run_key");
}

#[test]
fn fold_collapses_same_removed_item_across_stores_to_latest() {
    let out = fold_vss_findings(vec![
        p("Registry Run Key", r"C:\gone.exe", r"C:\ev\partition_0_vss_0\config\SOFTWARE"),
        p("Registry Run Key", r"C:\gone.exe", r"C:\ev\partition_0_vss_3\config\SOFTWARE"),
        p("Registry Run Key", r"C:\gone.exe", r"C:\ev\partition_0_vss_1\config\SOFTWARE"),
    ]);
    assert_eq!(out.len(), 1);
    assert!(out[0].source.starts_with("vss:3:"), "{}", out[0].source);
}

#[test]
fn fold_distinguishes_technique_and_access() {
    let mut user = p("Registry Run Key", r"C:\x.exe", r"C:\ev\partition_0_vss_1\Users\bob\NTUSER.DAT");
    user.access_gained = "User".into();
    let out = fold_vss_findings(vec![p("Registry Run Key", r"C:\x.exe", r"C:\ev\partition_0\config\SOFTWARE"), user]);
    assert_eq!(out.len(), 2, "same value but different access is a different persistence");
}

#[test]
fn fold_without_snapshots_is_identity() {
    let input = vec![p("A", "1", r"C:\ev\partition_0\SOFTWARE"), p("B", "2", r"C:\ev\C\Users\x\NTUSER.DAT")];
    assert_eq!(fold_vss_findings(input.clone()), input);
}

#[test]
fn end_to_end_live_and_snapshot_hives() {
    let d = TempDir::new("vss_e2e");
    let mut live = HiveBuilder::software();
    live.sz(r"Microsoft\Windows\CurrentVersion\Run", "Keeps", r"C:\keeps.exe");
    live.write(&d.join("partition_0/config/SOFTWARE"));
    let mut snap = HiveBuilder::software();
    snap.sz(r"Microsoft\Windows\CurrentVersion\Run", "Keeps", r"C:\keeps.exe")
        .sz(r"Microsoft\Windows\CurrentVersion\Run", "Wiped", r"C:\wiped.exe")
        .sz(r"Microsoft\Active Setup\Installed Components\{X}", "StubPath", r"C:\stub.exe");
    snap.write(&d.join("partition_0_vss_1/config/SOFTWARE"));
    d.write(&format!("partition_0_vss_1/{VSS_INFO_FILE}"), b"created=2026-03-01 10:00:00 UTC\nsequence=5\n");

    let mut set = HiveSet::discover(&d.path);
    assert_eq!(set.len(), 2);
    let all = fold_vss_findings(run_all(&mut set, &d.path));
    let keeps: Vec<&Persistence> = all.iter().filter(|x| x.value == r"C:\keeps.exe").collect();
    assert_eq!(keeps.len(), 1);
    assert!(keeps[0].source.is_empty());
    let wiped = all.iter().find(|x| x.value == r"C:\wiped.exe").unwrap();
    assert_eq!(wiped.source, "vss:1:2026-03-01 10:00:00 UTC");
    let stub = all.iter().find(|x| x.value == r"C:\stub.exe").unwrap();
    assert!(stub.source.starts_with("vss:1:"));
    let e = persistence_to_event(wiped, "HOST");
    assert_eq!(e.artifact, "windows:persistence:removed_since_vss:registry_run_key");
    assert!(e.parentprocessname.contains("2026-03-01 10:00:00 UTC"));
}
