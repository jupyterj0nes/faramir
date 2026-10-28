//! discover_hives across collector layouts and the end-to-end Windows pipeline.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::*;
use faramir::windows::{run_all, HiveSet};

fn kinds(infos: &[HiveInfo]) -> Vec<HiveKind> {
    infos.iter().map(|i| i.kind).collect()
}

#[test]
fn kape_layout() {
    diag::clear();
    let d = TempDir::new("disc_kape");
    HiveBuilder::system().write(&d.join("C/Windows/System32/config/SYSTEM"));
    HiveBuilder::software().write(&d.join("C/Windows/System32/config/SOFTWARE"));
    HiveBuilder::default_hive().write(&d.join("C/Windows/System32/config/DEFAULT"));
    HiveBuilder::new(r"temRoot\System32\Config\SAM").write(&d.join("C/Windows/System32/config/SAM"));
    HiveBuilder::new(r"emRoot\System32\Config\SECURITY").write(&d.join("C/Windows/System32/config/SECURITY"));
    d.write("C/Windows/System32/config/SYSTEM.LOG1", b"log");
    d.write("C/Windows/System32/config/SOFTWARE.LOG2", b"log");
    HiveBuilder::ntuser("bob").write(&d.join("C/Users/bob/NTUSER.DAT"));
    d.write("C/Users/bob/NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf", b"x");
    d.write("C/Users/bob/NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms", b"x");
    HiveBuilder::usrclass("bob").write(&d.join("C/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat"));
    d.write("_kape.cli", b"x");

    let hives = discover_hives(&d.path);
    let mut k = kinds(&hives);
    k.sort_by_key(|k| k.label());
    assert_eq!(k, vec![HiveKind::Default, HiveKind::NtUser, HiveKind::Software, HiveKind::System, HiveKind::UsrClass]);
    assert!(diag::count("ERR_WIN_HIVE_COMPANION_SKIPPED") >= 4);
    assert!(!diag::has("ERR_WIN_HIVE_SIGNATURE"));
}

#[test]
fn velociraptor_layout_with_encoded_drive() {
    let d = TempDir::new("disc_velo");
    HiveBuilder::system().write(&d.join("uploads/auto/C%3A/Windows/System32/config/SYSTEM"));
    HiveBuilder::ntuser("alice").write(&d.join("uploads/auto/C%3A/Users/alice/NTUSER.DAT"));
    d.write("client_info.json", b"{}");
    let hives = discover_hives(&d.path);
    assert_eq!(hives.len(), 2);
}

#[test]
fn image_dump_layout() {
    let d = TempDir::new("disc_image");
    HiveBuilder::system().write(&d.join("partition_0/config/SYSTEM"));
    HiveBuilder::software().write(&d.join("partition_0/config/SOFTWARE"));
    HiveBuilder::ntuser("bob").write(&d.join("partition_0/Users/bob_NTUSER.DAT"));
    HiveBuilder::new(r"AppCompat\Programs\Amcache.hve").write(&d.join("partition_0/AppCompat/Amcache.hve"));
    let hives = discover_hives(&d.path);
    let mut k = kinds(&hives);
    k.sort_by_key(|k| k.label());
    assert_eq!(k, vec![HiveKind::NtUser, HiveKind::Software, HiveKind::System]);
    let bob = hives.iter().find(|h| h.kind == HiveKind::NtUser).unwrap();
    assert_eq!(bob.name_kind, HiveKind::NtUser);
    assert!(bob.file_name().starts_with("bob_"));
}

#[test]
fn flattened_and_lowercase_names() {
    let d = TempDir::new("disc_flat");
    HiveBuilder::software().write(&d.join("output/C_Windows_System32_config_SOFTWARE"));
    HiveBuilder::system().write(&d.join("output/system"));
    HiveBuilder::ntuser("x").write(&d.join("output/c_users_x_ntuser.dat"));
    let hives = discover_hives(&d.path);
    let mut k = kinds(&hives);
    k.sort_by_key(|k| k.label());
    assert_eq!(k, vec![HiveKind::NtUser, HiveKind::Software, HiveKind::System]);
}

#[test]
fn randomly_named_hive_is_sniffed_by_extension() {
    let d = TempDir::new("disc_sniff_ext");
    HiveBuilder::ntuser("bob").write(&d.join("export/artifact_17.bin"));
    HiveBuilder::software().write(&d.join("export/artifact_18.dat"));
    d.write("export/notes.txt", b"not a hive");
    let hives = discover_hives(&d.path);
    let mut k = kinds(&hives);
    k.sort_by_key(|k| k.label());
    assert_eq!(k, vec![HiveKind::NtUser, HiveKind::Software]);
}

#[test]
fn extensionless_4k_multiple_file_is_sniffed() {
    let d = TempDir::new("disc_sniff_noext");
    HiveBuilder::system().write(&d.join("blobs/0001"));
    d.write("blobs/0002", &vec![0u8; 8192]); // regular zeros, same size, not regf
    let hives = discover_hives(&d.path);
    assert_eq!(kinds(&hives), vec![HiveKind::System]);
}

#[test]
fn file_named_like_hive_but_not_regf_is_an_error() {
    diag::clear();
    let d = TempDir::new("disc_fake");
    d.write("config/SYSTEM", b"definitely not a registry hive, just text");
    let hives = discover_hives(&d.path);
    assert!(hives.is_empty());
    assert!(diag::has("ERR_WIN_HIVE_SIGNATURE"));
}

#[test]
fn empty_file_named_like_hive_is_ignored_quietly() {
    diag::clear();
    let d = TempDir::new("disc_empty");
    d.write("config/SOFTWARE", b"");
    assert!(discover_hives(&d.path).is_empty());
    assert!(!diag::has("ERR_WIN_HIVE_SIGNATURE"));
}

#[test]
fn transaction_log_named_like_hive_is_rejected() {
    diag::clear();
    let d = TempDir::new("disc_lognamed");
    let mut b = HiveBuilder::software().build();
    patch_base_block(&mut b, 1, 1, 6);
    d.write("SOFTWARE", &b);
    assert!(discover_hives(&d.path).is_empty());
    assert!(diag::has("ERR_WIN_HIVE_NOT_PRIMARY"));
}

#[test]
fn non_persistence_hives_are_excluded() {
    let d = TempDir::new("disc_excl");
    HiveBuilder::new(r"temRoot\System32\Config\SAM").write(&d.join("SAM"));
    HiveBuilder::new(r"\Device\HarddiskVolume1\Boot\BCD").write(&d.join("BCD"));
    HiveBuilder::new(r"emRoot\System32\Config\COMPONENTS").write(&d.join("COMPONENTS"));
    assert!(discover_hives(&d.path).is_empty());
}

#[test]
fn single_file_root() {
    let d = TempDir::new("disc_single");
    let p = HiveBuilder::software().write(&d.join("SOFTWARE"));
    let hives = discover_hives(&p);
    assert_eq!(hives.len(), 1);
    assert_eq!(hives[0].evidence_root, d.path);
}

#[test]
fn missing_root_records_io_error() {
    diag::clear();
    let hives = discover_hives(std::path::Path::new("Z:/definitely/missing/root"));
    assert!(hives.is_empty());
    assert!(diag::has("ERR_WIN_HIVE_DISCOVERY_IO"));
}

#[test]
fn dirty_hives_are_flagged_in_info() {
    let d = TempDir::new("disc_dirty");
    HiveBuilder::software().write_with(&d.join("SOFTWARE"), 4, 3);
    let hives = discover_hives(&d.path);
    assert_eq!(hives.len(), 1);
    assert!(hives[0].is_dirty());
}

#[test]
fn unknown_hive_header_and_name_is_still_discovered_when_extension_hints() {
    diag::clear();
    let d = TempDir::new("disc_unknown");
    HiveBuilder::anonymous().write(&d.join("x/evidence.hve"));
    let hives = discover_hives(&d.path);
    assert_eq!(kinds(&hives), vec![HiveKind::Unknown]);
    assert!(diag::has("ERR_WIN_HIVE_KIND_UNRESOLVED"));
}

#[test]
fn hive_set_discover_matches_discover_hives() {
    let d = TempDir::new("disc_set");
    HiveBuilder::software().write(&d.join("a/SOFTWARE"));
    HiveBuilder::system().write(&d.join("a/SYSTEM"));
    let set = HiveSet::discover(&d.path);
    assert_eq!(set.len(), 2);
    assert_eq!(set.kinds().len(), discover_hives(&d.path).len());
}

// ─── end-to-end on a synthetic triage ────────────────────────────────────────

#[test]
fn full_triage_run_all_end_to_end() {
    diag::clear();
    let d = TempDir::new("disc_e2e");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Run", "Updater", r"C:\ProgramData\u.exe");
    let mut sw_step = sw.clone();
    sw_step.sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", r"explorer.exe,C:\x.exe");
    let fx = build_dirty(&sw, &[&sw_step], 5, false);
    write_dirty(&d, "C/Windows/System32/config/SOFTWARE", &fx);

    let mut sys = HiveBuilder::system();
    sys.dword("Select", "Current", 1)
        .sz(r"ControlSet001\Services\EvilSvc", "ImagePath", r"C:\svc.exe")
        .sz(r"ControlSet001\Services\EvilSvc", "DisplayName", "Evil");
    sys.write(&d.join("C/Windows/System32/config/SYSTEM"));

    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Bob", r"C:\Users\bob\b.exe");
    nt.write(&d.join("C/Users/bob/NTUSER.DAT"));
    d.write("C/Users/bob/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/s.lnk", b"x");
    d.write("C/Windows/System32/Tasks/T", br#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>C:\t.exe</Command></Exec></Actions></Task>"#);
    d.write("C/Users/bob/Documents/WindowsPowerShell/profile.ps1", b"x");

    let mut set = HiveSet::discover(&d.path);
    assert_eq!(set.len(), 3);
    let all = run_all(&mut set, &d.path);
    let values: Vec<&str> = all.iter().map(|p| p.value.as_str()).collect();
    for expected in [r"C:\ProgramData\u.exe", r"C:\Users\bob\b.exe", "Evil", "Startup Folder", r"C:\t.exe"] {
        assert!(values.contains(&expected), "missing {expected}: {values:?}");
    }
    assert!(all.iter().any(|p| p.technique == "Winlogon shell Property" && p.path.contains(r"C:\x.exe")), "value added by the transaction log must be visible");
    assert!(all.iter().any(|p| p.technique == "PowerShell Profile Script"));
    assert!(set.recovery(0).map(|r| r.logs_applied).unwrap_or(false) || set.recovery(1).map(|r| r.logs_applied).unwrap_or(false) || set.recovery(2).map(|r| r.logs_applied).unwrap_or(false));
    assert!(!diag::has("ERR_WIN_TECH_PANIC"));
    assert!(diag::has("ERR_WIN_HIVE_RECOVERED"));

    let events: Vec<_> = all.iter().map(|p| faramir::windows::persistence_to_event(p, "HOST")).collect();
    assert!(events.iter().all(|e| e.computer == "HOST" && e.artifact.starts_with("windows:persistence:")));
}

#[test]
fn diagnostics_summary_counts_by_severity() {
    diag::clear();
    diag::record(faramir::errors::FaramirError::HiveSignatureInvalid("a".into()));
    diag::record(faramir::errors::FaramirError::TxLogNotFound("b".into()));
    diag::record(faramir::errors::FaramirError::HiveRecovered("c".into()));
    diag::record(faramir::errors::FaramirError::HiveRecovered("d".into()));
    let s = diag::summary();
    assert_eq!((s.errors, s.warnings, s.infos), (1, 1, 2));
    assert_eq!(s.total(), 4);
    assert_eq!(diag::count("ERR_WIN_HIVE_RECOVERED"), 2);
    let drained = diag::drain();
    assert_eq!(drained.len(), 4);
    assert!(diag::snapshot().is_empty());
    diag::set_quiet(true);
    assert!(diag::is_quiet());
    diag::set_quiet(false);
    diag::set_verbose(true);
    assert!(diag::is_verbose());
    diag::set_verbose(false);
    assert_eq!(diag::panic_message(&"boom"), "boom");
    assert_eq!(diag::panic_message(&String::from("bang")), "bang");
    assert_eq!(diag::panic_message(&42u8), "unknown panic payload");
}
