//! Locating LOG1/LOG2 across collector layouts and surviving damaged logs.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::{classify_hive, open_hive, open_hive_path, HiveFile, HiveKind};
use faramir::windows::techniques::string_value;
use faramir::windows::txlog::*;
use nt_hive2::SubPath;
use std::path::PathBuf;

const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

fn find_sz(hive: &mut HiveFile, path: &str, name: &str) -> Option<String> {
    let root = hive.root_key_node().ok()?;
    let key = root.subpath(path, hive).ok()??;
    let key = key.borrow();
    key.values().iter().find(|v| v.name().eq_ignore_ascii_case(name)).and_then(string_value)
}

/// SOFTWARE hive whose log adds Run\Marker = C:\marker.exe
fn software_fixture(secondary: u32) -> DirtyFixture {
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Marker", r"C:\marker.exe");
    build_dirty(&base, &[&step], secondary, false)
}

fn ntuser_fixture(user: &str, marker: &str) -> DirtyFixture {
    let base = HiveBuilder::ntuser(user);
    let mut step = HiveBuilder::ntuser(user);
    step.sz(&format!(r"SOFTWARE\{RUN}"), "Marker", marker);
    build_dirty(&base, &[&step], 5, false)
}

fn open_and_marker(hive: &std::path::Path, root: &std::path::Path, path: &str) -> (bool, Option<String>, Vec<PathBuf>) {
    diag::clear();
    clear_log_index();
    let info = classify_hive(hive, root).unwrap();
    let mut o = open_hive(&info).unwrap();
    let marker = find_sz(&mut o.hive, path, "Marker");
    let mut logs = Vec::new();
    logs.extend(o.recovery.log1.clone());
    logs.extend(o.recovery.log2.clone());
    (o.recovery.logs_applied, marker, logs)
}

// ─── layouts ─────────────────────────────────────────────────────────────────

#[test]
fn kape_layout_logs_next_to_hive() {
    let d = TempDir::new("loc_kape");
    let fx = software_fixture(5);
    let hive = write_dirty(&d, "C/Windows/System32/config/SOFTWARE", &fx);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs, vec![d.join("C/Windows/System32/config/SOFTWARE.LOG1")]);
    assert!(!diag::has("ERR_WIN_TX_LOG_REMOTE_MATCH"));
}

#[test]
fn lowercase_log_extension_is_found() {
    let d = TempDir::new("loc_lower");
    let fx = software_fixture(5);
    let hive = d.write("config/software", &fx.primary);
    d.write("config/software.log1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn image_dump_layout_user_prefixed_names() {
    let d = TempDir::new("loc_image");
    let fx = ntuser_fixture("bob", r"C:\bob.exe");
    let hive = write_dirty(&d, "partition_0/Users/bob_NTUSER.DAT", &fx);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, &format!(r"SOFTWARE\{RUN}"));
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\bob.exe"));
}

#[test]
fn flattened_collector_names_in_same_folder() {
    let d = TempDir::new("loc_flat");
    let fx = software_fixture(5);
    let hive = write_dirty(&d, "output/C_Windows_System32_config_SOFTWARE", &fx);
    let info = classify_hive(&hive, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::Software);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn flattened_collector_logs_in_separate_folder() {
    let d = TempDir::new("loc_flat_sep");
    let fx = software_fixture(5);
    let hive = d.write("output/registry/C_Windows_System32_config_SOFTWARE", &fx.primary);
    d.write("output/logs/C_Windows_System32_config_SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs, vec![d.join("output/logs/C_Windows_System32_config_SOFTWARE.LOG1")]);
    assert!(diag::has("ERR_WIN_TX_LOG_REMOTE_MATCH"));
}

#[test]
fn parallel_tree_canonical_names() {
    let d = TempDir::new("loc_parallel");
    let fx = software_fixture(5);
    let hive = d.write("files/C/Windows/System32/config/SOFTWARE", &fx.primary);
    d.write("logs/C/Windows/System32/config/SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn prefixed_hive_with_canonical_log_elsewhere() {
    let d = TempDir::new("loc_prefix_canon");
    let fx = ntuser_fixture("bob", r"C:\bob.exe");
    let hive = d.write("hives/bob_NTUSER.DAT", &fx.primary);
    d.write("Users/bob/NTUSER.DAT.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, &format!(r"SOFTWARE\{RUN}"));
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\bob.exe"));
}

#[test]
fn copy_suffix_hive_finds_plain_log() {
    let d = TempDir::new("loc_hve");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE.hve", &fx.primary);
    d.write("SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn two_users_are_disambiguated_by_embedded_name() {
    let d = TempDir::new("loc_users");
    let bob = ntuser_fixture("bob", r"C:\bob.exe");
    let alice = ntuser_fixture("alice", r"C:\alice.exe");
    let bob_hive = d.write("files/Users/bob/NTUSER.DAT", &bob.primary);
    d.write("files/Users/alice/NTUSER.DAT", &alice.primary);
    // logs in a flat folder where only the header can tell them apart
    d.write("logs/1/NTUSER.DAT.LOG1", &alice.log1);
    d.write("logs/2/NTUSER.DAT.LOG1", &bob.log1);
    let (applied, marker, logs) = open_and_marker(&bob_hive, &d.path, &format!(r"SOFTWARE\{RUN}"));
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\bob.exe"));
    assert_eq!(logs, vec![d.join("logs/2/NTUSER.DAT.LOG1")]);
    assert!(diag::has("ERR_WIN_TX_LOG_HIVE_MISMATCH"), "alice's log must be rejected");
}

#[test]
fn foreign_log_in_same_folder_is_rejected_and_remote_one_used() {
    let d = TempDir::new("loc_foreign");
    let sw = software_fixture(5);
    let sys = {
        let base = HiveBuilder::system();
        let step = HiveBuilder::system();
        build_dirty(&base, &[&step], 5, false)
    };
    let hive = d.write("a/SOFTWARE", &sw.primary);
    d.write("a/SOFTWARE.LOG1", &sys.log1); // actually SYSTEM's log
    d.write("b/SOFTWARE.LOG1", &sw.log1);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs, vec![d.join("b/SOFTWARE.LOG1")]);
    assert!(diag::has("ERR_WIN_TX_LOG_HIVE_MISMATCH"));
}

#[test]
fn equally_good_candidates_raise_ambiguous_warning() {
    let d = TempDir::new("loc_ambig");
    let fx = software_fixture(5);
    let hive = d.write("hives/SOFTWARE", &fx.primary);
    d.write("x/SOFTWARE.LOG1", &fx.log1);
    d.write("y/SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert!(diag::has("ERR_WIN_TX_LOG_AMBIGUOUS"));
}

#[test]
fn same_folder_beats_remote_even_with_better_name() {
    let d = TempDir::new("loc_samedir");
    let fx = software_fixture(5);
    let hive = d.write("cfg/SOFTWARE", &fx.primary);
    d.write("cfg/SOFTWARE.LOG1", &fx.log1);
    d.write("elsewhere/SOFTWARE.LOG1", &fx.log1);
    let (_, _, logs) = open_and_marker(&hive, &d.path, RUN);
    assert_eq!(logs, vec![d.join("cfg/SOFTWARE.LOG1")]);
    assert!(!diag::has("ERR_WIN_TX_LOG_REMOTE_MATCH"));
}

// ─── missing / unusable logs ─────────────────────────────────────────────────

#[test]
fn no_logs_anywhere() {
    let d = TempDir::new("loc_none");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &fx.primary);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(!applied);
    assert_eq!(marker, None);
    assert!(logs.is_empty());
    assert!(diag::has("ERR_WIN_TX_LOG_NOT_FOUND"));
}

#[test]
fn only_legacy_log_present() {
    let d = TempDir::new("loc_legacy");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &fx.primary);
    let mut legacy = fx.log1.clone();
    patch_base_block(&mut legacy, 6, 6, 1);
    d.write("SOFTWARE.LOG", &legacy);
    let (applied, _, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(!applied);
    assert!(diag::has("ERR_WIN_TX_LOG_LEGACY"));
    assert!(diag::has("ERR_WIN_HIVE_DIRTY"));
}

#[test]
fn garbage_log_is_rejected_hive_still_usable() {
    let d = TempDir::new("loc_garbage");
    let mut base = HiveBuilder::software();
    base.sz(RUN, "Existing", r"C:\e.exe");
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Existing", r"C:\e.exe");
    step.sz(RUN, "Marker", r"C:\m.exe");
    let fx = build_dirty(&base, &[&step], 5, false);
    let hive = d.write("SOFTWARE", &fx.primary);
    d.write("SOFTWARE.LOG1", &vec![0x41u8; 4096]);
    diag::clear();
    clear_log_index();
    let mut o = open_hive_path(&hive).unwrap();
    assert!(!o.recovery.logs_applied);
    assert!(diag::has("ERR_WIN_TX_LOG_SIGNATURE"));
    assert!(diag::has("ERR_WIN_HIVE_DIRTY"));
    assert_eq!(find_sz(&mut o.hive, RUN, "Existing").as_deref(), Some(r"C:\e.exe"));
    assert_eq!(find_sz(&mut o.hive, RUN, "Marker"), None);
}

#[test]
fn truncated_log_tail_is_cut_and_valid_prefix_applied() {
    let d = TempDir::new("loc_partial");
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(RUN, "First", r"C:\1.exe");
    let mut s2 = HiveBuilder::software();
    s2.sz(RUN, "First", r"C:\1.exe");
    s2.sz(RUN, "Second", r"C:\2.exe");
    let fx = build_dirty(&base, &[&s1, &s2], 5, false);
    let hive = d.write("SOFTWARE", &fx.primary);
    let cut = fx.log1.len() - 700; // damages the second entry only
    d.write("SOFTWARE.LOG1", &fx.log1[..cut]);
    diag::clear();
    clear_log_index();
    let mut o = open_hive_path(&hive).unwrap();
    assert!(o.recovery.logs_applied, "{:?}", diag::snapshot());
    assert!(diag::has("ERR_WIN_TX_LOG_TRUNCATED"));
    assert!(diag::has("ERR_WIN_TX_LOG_PARTIAL"));
    assert_eq!(find_sz(&mut o.hive, RUN, "First").as_deref(), Some(r"C:\1.exe"));
    assert_eq!(find_sz(&mut o.hive, RUN, "Second"), None);
}

#[test]
fn corrupt_page_reference_never_reaches_the_parser() {
    let d = TempDir::new("loc_pageref");
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(RUN, "First", r"C:\1.exe");
    let s2 = s1.clone();
    let fx = build_dirty(&base, &[&s1, &s2], 5, false);
    let hive = d.write("SOFTWARE", &fx.primary);
    let mut log = fx.log1.clone();
    let summary = inspect_transaction_log_bytes(std::path::Path::new("x"), &log).unwrap();
    let off2 = summary.entries[1].offset as usize;
    log[off2 + 44..off2 + 48].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    d.write("SOFTWARE.LOG1", &log);
    diag::clear();
    clear_log_index();
    let mut o = open_hive_path(&hive).unwrap();
    assert!(o.recovery.logs_applied, "{:?}", diag::snapshot());
    assert!(diag::has("ERR_WIN_TX_LOG_ENTRY_INVALID"));
    assert_eq!(find_sz(&mut o.hive, RUN, "First").as_deref(), Some(r"C:\1.exe"));
}

#[test]
fn stale_logs_only_leave_hive_dirty_with_warning() {
    let d = TempDir::new("loc_stale");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Marker", r"C:\m.exe");
    let fx = build_dirty(&base, &[&step], 5, false); // log seq 6
    let hive = d.write("SOFTWARE", &HiveBuilder::software().build_with(10, 9)); // hive is ahead
    let _ = fx.primary;
    d.write("SOFTWARE.LOG1", &fx.log1);
    diag::clear();
    clear_log_index();
    let o = open_hive_path(&hive).unwrap();
    assert!(!o.recovery.logs_applied);
    assert!(o.recovery.log1.is_some(), "the log is located and attributed");
    assert!(diag::has("ERR_WIN_TX_LOG_SEQUENCE"));
    assert!(!diag::has("ERR_WIN_HIVE_RECOVERED"));
}

#[test]
fn gap_log_is_not_applied() {
    let d = TempDir::new("loc_gap");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Marker", r"C:\m.exe");
    let fx = build_dirty(&base, &[&step], 20, false); // entry seq 21
    let hive = d.write("SOFTWARE", &HiveBuilder::software().build_with(6, 5));
    let _ = fx.primary;
    d.write("SOFTWARE.LOG1", &fx.log1);
    diag::clear();
    clear_log_index();
    let o = open_hive_path(&hive).unwrap();
    assert!(!o.recovery.logs_applied);
    assert!(diag::has("ERR_WIN_TX_LOG_SEQUENCE"));
}

#[test]
fn sequence_difference_greater_than_one_is_reported() {
    let d = TempDir::new("loc_seqdiff");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &HiveBuilder::software().build_with(9, 5));
    d.write("SOFTWARE.LOG1", &fx.log1);
    diag::clear();
    clear_log_index();
    let o = open_hive_path(&hive).unwrap();
    assert!(o.recovery.was_dirty);
    assert!(!o.recovery.logs_applied);
    assert!(diag::has("ERR_WIN_TX_LOG_SEQUENCE"));
}

#[test]
fn checksum_invalid_dirty_hive_opens_without_base_block() {
    let d = TempDir::new("loc_chk");
    let mut base = HiveBuilder::software();
    base.sz(RUN, "Existing", r"C:\e.exe");
    let mut bytes = base.build_with(6, 5);
    bytes[0x60] ^= 0x7f; // corrupt the embedded name, breaking the checksum
    let hive = d.write("SOFTWARE", &bytes);
    diag::clear();
    let mut o = open_hive_path(&hive).unwrap();
    assert!(o.recovery.opened_without_base_block);
    assert!(o.recovery.was_dirty);
    assert!(!o.recovery.logs_applied);
    assert!(diag::has("ERR_WIN_HIVE_CHECKSUM"));
    assert_eq!(find_sz(&mut o.hive, RUN, "Existing").as_deref(), Some(r"C:\e.exe"));
}

#[test]
fn clean_hive_never_touches_logs() {
    let d = TempDir::new("loc_clean");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "X", "y.exe");
    let hive = b.write(&d.join("SOFTWARE"));
    d.write("SOFTWARE.LOG1", &[0x41u8; 1024]);
    diag::clear();
    let o = open_hive_path(&hive).unwrap();
    assert!(!o.recovery.was_dirty);
    assert!(o.recovery.log1.is_none());
    assert!(!diag::has("ERR_WIN_TX_LOG_SIGNATURE"));
}

// ─── candidate search API ────────────────────────────────────────────────────

#[test]
fn find_candidates_orders_same_dir_first() {
    let d = TempDir::new("loc_cands");
    let fx = software_fixture(5);
    let hive = d.write("cfg/SOFTWARE", &fx.primary);
    d.write("cfg/SOFTWARE.LOG1", &fx.log1);
    d.write("other/HOST_SOFTWARE.LOG1", &fx.log1);
    d.write("other/SYSTEM.LOG1", &fx.log1);
    clear_log_index();
    let info = classify_hive(&hive, &d.path).unwrap();
    let c = find_log_candidates(&info, TxLogSlot::Log1);
    assert_eq!(c, vec![d.join("cfg/SOFTWARE.LOG1"), d.join("other/HOST_SOFTWARE.LOG1")]);
    assert!(find_log_candidates(&info, TxLogSlot::Log2).is_empty());
}

#[test]
fn log_index_is_cached_until_cleared() {
    let d = TempDir::new("loc_index");
    d.write("a/SOFTWARE.LOG1", b"x");
    clear_log_index();
    let first = log_index(&d.path);
    assert_eq!(first.len(), 1);
    d.write("b/SYSTEM.LOG2", b"y");
    let cached = log_index(&d.path);
    assert_eq!(cached.len(), 1, "cached");
    clear_log_index();
    assert_eq!(log_index(&d.path).len(), 2);
}

#[test]
fn locate_on_single_file_evidence_root_does_not_walk() {
    let d = TempDir::new("loc_file_root");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &fx.primary);
    d.write("SOFTWARE.LOG1", &fx.log1);
    clear_log_index();
    let info = classify_hive(&hive, &hive).unwrap(); // evidence root is the file itself
    let sel = locate_transaction_logs(&info);
    assert!(sel.log1.is_some());
    assert!(sel.has_matching());
    assert_eq!(sel.paths(), vec![d.join("SOFTWARE.LOG1")]);
}

#[test]
fn reconcile_pair_links_log1_and_log2_sequences() {
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(RUN, "A", "a");
    let mut s2 = HiveBuilder::software();
    s2.sz(RUN, "B", "b");
    let fx = build_dirty(&base, &[&s1, &s2], 5, true);
    let hive = faramir::windows::hives::HiveHeader::parse(&fx.primary, "h").unwrap();
    let l1 = inspect_transaction_log_bytes(std::path::Path::new("1"), &fx.log1).unwrap();
    let l2 = inspect_transaction_log_bytes(std::path::Path::new("2"), fx.log2.as_ref().unwrap()).unwrap();
    assert_eq!(relation_to_hive(&l2, &hive), TxLogRelation::Gap, "alone, LOG2 looks like a gap");
    let mut c1 = Some(TxLogCandidate { path: "1".into(), slot: TxLogSlot::Log1, same_directory: true, score: 0, relation: Some(relation_to_hive(&l1, &hive)), summary: Some(l1) });
    let mut c2 = Some(TxLogCandidate { path: "2".into(), slot: TxLogSlot::Log2, same_directory: true, score: 0, relation: Some(TxLogRelation::Gap), summary: Some(l2) });
    reconcile_pair(&mut c1, &mut c2, &hive);
    assert_eq!(c1.as_ref().unwrap().relation, Some(TxLogRelation::Matching));
    assert_eq!(c2.as_ref().unwrap().relation, Some(TxLogRelation::Matching));
}
