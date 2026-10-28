//! Structural validation of HvLE transaction logs before nt_hive2 sees them.
mod common;

use common::*;
use faramir::windows::hives::{HiveHeader, HiveKind};
use faramir::windows::txlog::*;
use std::path::Path;

fn hive_bytes() -> Vec<u8> {
    let mut b = HiveBuilder::software();
    b.sz(r"Microsoft\Windows\CurrentVersion\Run", "x", "y");
    b.build_with(6, 5)
}

fn page(n: usize) -> Vec<u8> {
    vec![0xAB; n]
}

fn log_with(entries: &[LogEntryDef]) -> Vec<u8> {
    build_log(&hive_bytes(), entries)
}

fn entry(seq: u32, pages: Vec<(u32, Vec<u8>)>) -> LogEntryDef {
    LogEntryDef { sequence: seq, hbin_data_size: 8192, pages }
}

fn inspect(bytes: &[u8]) -> Result<TxLogSummary, faramir::errors::FaramirError> {
    inspect_transaction_log_bytes(Path::new("test.LOG1"), bytes)
}

// ─── fatal rejections ────────────────────────────────────────────────────────

#[test]
fn rejects_file_shorter_than_a_sector() {
    assert_eq!(inspect(&[0u8; 100]).unwrap_err().code(), "ERR_WIN_TX_LOG_TRUNCATED");
}
#[test]
fn rejects_missing_regf_signature() {
    assert_eq!(inspect(&[0u8; 1024]).unwrap_err().code(), "ERR_WIN_TX_LOG_SIGNATURE");
}
#[test]
fn rejects_legacy_type_1() {
    let mut b = hive_bytes();
    patch_base_block(&mut b, 6, 6, 1);
    assert_eq!(inspect(&b[..1024]).unwrap_err().code(), "ERR_WIN_TX_LOG_LEGACY");
}
#[test]
fn rejects_legacy_type_2() {
    let mut b = hive_bytes();
    patch_base_block(&mut b, 6, 6, 2);
    assert_eq!(inspect(&b[..1024]).unwrap_err().code(), "ERR_WIN_TX_LOG_LEGACY");
}
#[test]
fn rejects_primary_hive_passed_as_log() {
    let b = hive_bytes();
    let e = inspect(&b).unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_TX_LOG_SIGNATURE");
    assert!(e.detail().contains("primary hive"));
}
#[test]
fn rejects_unknown_file_type() {
    let mut b = hive_bytes();
    patch_base_block(&mut b, 6, 6, 42);
    assert_eq!(inspect(&b[..1024]).unwrap_err().code(), "ERR_WIN_TX_LOG_SIGNATURE");
}
#[test]
fn rejects_log_without_entries() {
    let b = log_with(&[]);
    assert_eq!(b.len(), 512);
    assert_eq!(inspect(&b).unwrap_err().code(), "ERR_WIN_TX_LOG_EMPTY");
}
#[test]
fn rejects_log_with_only_zero_padding() {
    let mut b = log_with(&[]);
    b.extend_from_slice(&[0u8; 4096]);
    assert_eq!(inspect(&b).unwrap_err().code(), "ERR_WIN_TX_LOG_EMPTY");
}
#[test]
fn rejects_log_whose_first_entry_is_invalid() {
    let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
    b[512 + 20..512 + 24].copy_from_slice(&0u32.to_le_bytes()); // zero dirty pages
    let e = inspect(&b).unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_TX_LOG_EMPTY");
}

// ─── valid logs ──────────────────────────────────────────────────────────────

#[test]
fn single_entry_summary() {
    let b = log_with(&[entry(6, vec![(0, page(4096))])]);
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert_eq!(s.entries[0].sequence, 6);
    assert_eq!(s.entries[0].offset, 512);
    assert_eq!(s.entries[0].dirty_pages, 1);
    assert_eq!(s.entries[0].payload_bytes, 4096);
    assert_eq!(s.entries[0].hbin_data_size, 8192);
    assert_eq!(s.entries[0].size as usize, (40 + 8 + 4096usize).div_ceil(512) * 512);
    assert_eq!(s.file_len, b.len() as u64);
    assert_eq!(s.usable_len, s.file_len);
    assert!(!s.needs_sanitizing());
    assert!(s.problems.is_empty());
    assert_eq!(s.first_sequence(), Some(6));
    assert_eq!(s.last_sequence(), Some(6));
    assert_eq!(s.embedded_name(), r"emRoot\System32\Config\SOFTWARE");
    assert!(s.header.is_new_log());
    assert!(s.header.checksum_valid());
}
#[test]
fn multiple_entries_consecutive() {
    let b = log_with(&[entry(6, vec![(0, page(4096))]), entry(7, vec![(4096, page(4096))]), entry(8, vec![(0, page(512))])]);
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.iter().map(|e| e.sequence).collect::<Vec<_>>(), vec![6, 7, 8]);
    assert!(s.problems.is_empty());
}
#[test]
fn multiple_pages_in_one_entry() {
    let b = log_with(&[entry(6, vec![(0, page(4096)), (4096, page(4096))])]);
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries[0].dirty_pages, 2);
    assert_eq!(s.entries[0].payload_bytes, 8192);
}
#[test]
fn trailing_zero_padding_is_fine() {
    let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
    b.extend_from_slice(&[0u8; 8192]);
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.is_empty());
    assert!(!s.needs_sanitizing());
}
#[test]
fn entries_after_garbage_magic_are_ignored() {
    let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
    b.extend_from_slice(b"JUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNK");
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.is_empty());
}
#[test]
fn sequence_gap_is_reported_but_not_fatal() {
    let b = log_with(&[entry(6, vec![(0, page(4096))]), entry(9, vec![(0, page(4096))])]);
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 2);
    assert!(s.problems.iter().any(|p| p.code() == "ERR_WIN_TX_LOG_SEQUENCE"));
}
#[test]
fn log_base_block_checksum_problem_is_non_fatal() {
    let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
    b[0x40] ^= 0x55;
    let s = inspect(&b).unwrap();
    assert!(s.problems.iter().any(|p| p.code() == "ERR_WIN_HIVE_CHECKSUM"));
    assert_eq!(s.entries.len(), 1);
}

// ─── damaged tails are cut, never fatal when a prefix is valid ───────────────

fn two_entries() -> Vec<u8> {
    log_with(&[entry(6, vec![(0, page(4096))]), entry(7, vec![(0, page(4096))])])
}

fn second_entry_offset(b: &[u8]) -> usize {
    let s = inspect(b).unwrap();
    s.entries[1].offset as usize
}

#[test]
fn truncated_second_entry_keeps_first() {
    let b = two_entries();
    let off2 = second_entry_offset(&b);
    let cut = &b[..off2 + 1000];
    let s = inspect(cut).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.needs_sanitizing());
    assert_eq!(s.usable_len, off2 as u64);
    assert!(s.problems.iter().any(|p| p.code() == "ERR_WIN_TX_LOG_TRUNCATED"));
}
#[test]
fn entry_size_smaller_than_header() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 4..off2 + 8].copy_from_slice(&16u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.code() == "ERR_WIN_TX_LOG_ENTRY_INVALID" && p.detail().contains("smaller than header")));
}
#[test]
fn entry_size_not_sector_aligned() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 4..off2 + 8].copy_from_slice(&(4096u32 + 100).to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("not a multiple")));
}
#[test]
fn entry_with_unexpected_flags() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 8..off2 + 12].copy_from_slice(&0xF0u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("flags")));
}
#[test]
fn entry_with_zero_dirty_pages() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 20..off2 + 24].copy_from_slice(&0u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("zero dirty pages")));
}
#[test]
fn entry_with_absurd_page_count() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 20..off2 + 24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("do not fit")));
}
#[test]
fn entry_with_unaligned_hbin_size() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 16..off2 + 20].copy_from_slice(&4097u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("4096-aligned")));
}
#[test]
fn page_reference_with_zero_size() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 44..off2 + 48].copy_from_slice(&0u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("zero size")));
}
#[test]
fn page_reference_exceeding_hbin_size_is_rejected() {
    // This is the exact shape that made nt_hive2 allocate/panic on truncated triages.
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 44..off2 + 48].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.needs_sanitizing());
    assert!(s.problems.iter().any(|p| p.detail().contains("exceeds hbin data size")));
}
#[test]
fn page_reference_offset_overflow_is_rejected() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    b[off2 + 40..off2 + 44].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    b[off2 + 44..off2 + 48].copy_from_slice(&0x100u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
}
#[test]
fn payload_larger_than_entry_is_rejected() {
    let mut b = two_entries();
    let off2 = second_entry_offset(&b);
    // claim a 8192-byte page (fits hbin) inside an entry sized for 4096
    b[off2 + 44..off2 + 48].copy_from_slice(&8192u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 1);
    assert!(s.problems.iter().any(|p| p.detail().contains("does not fit in entry")));
}
#[test]
fn damage_in_third_entry_keeps_two() {
    let mut b = log_with(&[entry(6, vec![(0, page(512))]), entry(7, vec![(0, page(512))]), entry(8, vec![(0, page(512))])]);
    let s = inspect(&b).unwrap();
    let off3 = s.entries[2].offset as usize;
    b[off3 + 20..off3 + 24].copy_from_slice(&0u32.to_le_bytes());
    let s = inspect(&b).unwrap();
    assert_eq!(s.entries.len(), 2);
    assert_eq!(s.usable_len, off3 as u64);
}

// ─── relation to hive ────────────────────────────────────────────────────────

fn hive_header(primary: u32, secondary: u32, name: &str) -> HiveHeader {
    HiveHeader::parse(&base_block(primary, secondary, 0x20, 4096, name, 0, 5), "h").unwrap()
}

#[test]
fn relation_matching() {
    let s = inspect(&log_with(&[entry(6, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"emRoot\System32\Config\SOFTWARE")), TxLogRelation::Matching);
}
#[test]
fn relation_stale() {
    let s = inspect(&log_with(&[entry(4, vec![(0, page(512))]), entry(5, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"emRoot\System32\Config\SOFTWARE")), TxLogRelation::Stale);
}
#[test]
fn relation_gap() {
    let s = inspect(&log_with(&[entry(9, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"emRoot\System32\Config\SOFTWARE")), TxLogRelation::Gap);
}
#[test]
fn relation_foreign_by_embedded_name() {
    let s = inspect(&log_with(&[entry(6, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"emRoot\System32\Config\SYSTEM")), TxLogRelation::Foreign);
}
#[test]
fn relation_blank_hive_name_is_not_foreign() {
    let s = inspect(&log_with(&[entry(6, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, "")), TxLogRelation::Matching);
}
#[test]
fn relation_name_compare_is_case_insensitive() {
    let s = inspect(&log_with(&[entry(6, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"EMROOT\SYSTEM32\CONFIG\SOFTWARE")), TxLogRelation::Matching);
}
#[test]
fn relation_matching_when_log_starts_before_secondary_but_continues_after() {
    let s = inspect(&log_with(&[entry(5, vec![(0, page(512))]), entry(6, vec![(0, page(512))])])).unwrap();
    assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"emRoot\System32\Config\SOFTWARE")), TxLogRelation::Matching);
}

// ─── name matching ───────────────────────────────────────────────────────────

#[test]
fn name_matches_exact() {
    assert!(name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG1", TxLogSlot::Log1));
    assert!(name_matches("SYSTEM", HiveKind::System, "system.log1", TxLogSlot::Log1));
    assert!(!name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG2", TxLogSlot::Log1));
}
#[test]
fn name_matches_prefixed_hive_and_log() {
    assert!(name_matches("bob_NTUSER.DAT", HiveKind::NtUser, "bob_NTUSER.DAT.LOG1", TxLogSlot::Log1));
}
#[test]
fn name_matches_prefixed_hive_canonical_log() {
    assert!(name_matches("bob_NTUSER.DAT", HiveKind::NtUser, "NTUSER.DAT.LOG1", TxLogSlot::Log1));
}
#[test]
fn name_matches_canonical_hive_prefixed_log() {
    assert!(name_matches("SOFTWARE", HiveKind::Software, "HOST_SOFTWARE.LOG2", TxLogSlot::Log2));
    assert!(name_matches("SOFTWARE", HiveKind::Software, "C_Windows_System32_config_SOFTWARE.LOG2", TxLogSlot::Log2));
}
#[test]
fn name_matches_copy_suffix_hive() {
    assert!(name_matches("SOFTWARE.hve", HiveKind::Software, "SOFTWARE.LOG1", TxLogSlot::Log1));
}
#[test]
fn name_matches_legacy_slot() {
    assert!(name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG", TxLogSlot::Legacy));
    assert!(!name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG1", TxLogSlot::Legacy));
}
#[test]
fn name_rejects_other_hives() {
    assert!(!name_matches("SYSTEM", HiveKind::System, "SOFTWARE.LOG1", TxLogSlot::Log1));
    assert!(!name_matches("NTUSER.DAT", HiveKind::NtUser, "UsrClass.dat.LOG1", TxLogSlot::Log1));
}
#[test]
fn name_unknown_kind_only_exact() {
    assert!(name_matches("blob.bin", HiveKind::Unknown, "blob.bin.LOG1", TxLogSlot::Log1));
    assert!(!name_matches("blob.bin", HiveKind::Unknown, "SYSTEM.LOG1", TxLogSlot::Log1));
}
#[test]
fn slot_extensions() {
    assert_eq!(TxLogSlot::Log1.extension(), ".LOG1");
    assert_eq!(TxLogSlot::Log2.extension(), ".LOG2");
    assert_eq!(TxLogSlot::Legacy.extension(), ".LOG");
}

// ─── scoring ─────────────────────────────────────────────────────────────────

#[test]
fn score_same_directory_dominates() {
    let h = Path::new("/ev/C/Windows/System32/config/SYSTEM");
    let same = score_candidate(h, Path::new("/ev/C/Windows/System32/config/SYSTEM.LOG1"));
    let other = score_candidate(h, Path::new("/ev/logs/config/SYSTEM.LOG1"));
    assert!(same > other);
    assert!(same >= 1000);
}
#[test]
fn score_prefers_matching_parent_chain() {
    let h = Path::new("/ev/files/C/Users/bob/NTUSER.DAT");
    let bob = score_candidate(h, Path::new("/ev/logs/C/Users/bob/NTUSER.DAT.LOG1"));
    let alice = score_candidate(h, Path::new("/ev/logs/C/Users/alice/NTUSER.DAT.LOG1"));
    assert!(bob > alice, "{bob} vs {alice}");
}
#[test]
fn score_rewards_exact_name_prefix() {
    let h = Path::new("/ev/x/bob_NTUSER.DAT");
    let exact = score_candidate(h, Path::new("/ev/y/bob_NTUSER.DAT.LOG1"));
    let canon = score_candidate(h, Path::new("/ev/y/NTUSER.DAT.LOG1"));
    assert!(exact > canon);
}
#[test]
fn score_is_case_insensitive_on_components() {
    let h = Path::new("/ev/C/Users/Bob/NTUSER.DAT");
    let a = score_candidate(h, Path::new("/ev/logs/users/bob/NTUSER.DAT.LOG1"));
    let b = score_candidate(h, Path::new("/ev/logs/users/alice/NTUSER.DAT.LOG1"));
    assert!(a > b);
}

// ─── on-disk inspection ──────────────────────────────────────────────────────

#[test]
fn inspect_missing_file() {
    let e = inspect_transaction_log(Path::new("Z:/nope/SYSTEM.LOG1")).unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_TX_LOG_OPEN");
}
#[test]
fn inspect_real_windows_log_fixtures() {
    let l1 = inspect_transaction_log(&fixture("dirty_hive/NewDirtyHive.LOG1")).unwrap();
    assert_eq!(l1.entries.len(), 1);
    assert_eq!(l1.entries[0].sequence, 2);
    assert_eq!(l1.entries[0].dirty_pages, 1);
    assert_eq!(l1.entries[0].payload_bytes, 0x5000);
    assert!(l1.problems.is_empty(), "{:?}", l1.problems);
    assert!(!l1.needs_sanitizing());

    let l2 = inspect_transaction_log(&fixture("dirty_hive/NewDirtyHive.LOG2")).unwrap();
    assert!(!l2.entries.is_empty());
    assert!(l2.problems.is_empty(), "{:?}", l2.problems);

    let hive = faramir::windows::hives::read_hive_header(&fixture("dirty_hive/NewDirtyHive")).unwrap();
    assert_eq!(relation_to_hive(&l1, &hive), TxLogRelation::Stale);
    assert_eq!(relation_to_hive(&l2, &hive), TxLogRelation::Matching);
}
#[test]
fn selection_helpers() {
    let sel = TxLogSelection::default();
    assert!(sel.is_empty());
    assert!(sel.usable().is_empty());
    assert!(sel.paths().is_empty());
}
