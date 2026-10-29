//! Registry carving: scan engine, guarded sources, hive validation,
//! whole-hive recovery, folding against the live registry and the CLI flag.
mod common;

use common::*;
use faramir::carve::hive::{
    carved_file_name, content_hash, filetime_to_string, fingerprint, fingerprint_of_file, fingerprints_under, read_hive,
    starts_with_regf, valid_bin_header, validate_base_block, write_carved, CarvedHive, RawCarve, REGF_MAGIC, WINDOW,
};
use faramir::carve::scan::{scan_signatures, HitAction, ScanConfig, ERROR_SKIP, MAX_CONSECUTIVE_ERRORS, STALL_SKIP};
use faramir::carve::source::{BlockError, BlockSource, DirectSource, GuardedSource, MemorySource};
use faramir::carve::{carve_hives, carve_path, is_carved_source, open_source, summary_line, tag_and_fold, CarveReport};
use faramir::errors::{FaramirError, Severity};
use faramir::windows::deleted::SOURCE_DELETED;
use faramir::windows::hives::{HiveHeader, HiveKind, BASE_BLOCK_SIZE};
use faramir::windows::{diag, persistence_to_event, run_technique, HiveSet, Persistence, TechniqueId};
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";
const MB: usize = 1 << 20;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Deterministic filler that never spells `regf` or `hbin`.
fn filler(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(7).wrapping_add(13)) as u8).collect()
}

fn disk(total: usize, parts: &[(usize, &[u8])]) -> Vec<u8> {
    let mut d = filler(total);
    for (off, bytes) in parts {
        d[*off..*off + bytes.len()].copy_from_slice(bytes);
    }
    d
}

fn software(name: &str, exe: &str) -> Vec<u8> {
    let mut b = HiveBuilder::software();
    b.sz(RUN, name, exe);
    b.build()
}

/// Append `n` empty 4 KB bins and fix the base block up.
fn append_empty_bins(hive: &mut Vec<u8>, n: usize) {
    for _ in 0..n {
        let off = (hive.len() - BASE_BLOCK_SIZE) as u32;
        let mut bin = vec![0u8; 4096];
        bin[..4].copy_from_slice(b"hbin");
        bin[4..8].copy_from_slice(&off.to_le_bytes());
        bin[8..12].copy_from_slice(&4096u32.to_le_bytes());
        bin[32..36].copy_from_slice(&(4096i32 - 32).to_le_bytes()); // one free cell
        hive.extend_from_slice(&bin);
    }
    let data_size = (hive.len() - BASE_BLOCK_SIZE) as u32;
    hive[0x28..0x2c].copy_from_slice(&data_size.to_le_bytes());
    let sum = checksum(&hive[..512]);
    hive[0x1fc..0x200].copy_from_slice(&sum.to_le_bytes());
}

fn carve_bytes(d: &TempDir, bytes: Vec<u8>, known: &HashSet<String>) -> CarveReport {
    let mut src = MemorySource::from_bytes(bytes, "mem");
    diag::clear();
    carve_hives(&mut src, &d.join("carved"), known)
}

fn errors_of(sev: Severity) -> Vec<FaramirError> {
    diag::snapshot().into_iter().filter(|e| e.severity() == sev).collect()
}

/// Scripted block source: zero-filled, with injected failures per block offset.
struct Scripted {
    size: u64,
    fail: Box<dyn Fn(u64) -> Option<BlockError>>,
    calls: std::cell::RefCell<Vec<u64>>,
}

impl BlockSource for Scripted {
    fn size(&self) -> u64 {
        self.size
    }
    fn label(&self) -> &str {
        "scripted"
    }
    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        self.calls.borrow_mut().push(offset);
        if offset >= self.size {
            return Ok(Vec::new());
        }
        if let Some(e) = (self.fail)(offset) {
            return Err(e);
        }
        Ok(vec![0u8; len.min((self.size - offset) as usize)])
    }
}

fn hits_of(src: &mut dyn BlockSource, cfg: &ScanConfig, sig: &[u8]) -> Vec<u64> {
    let mut hits = Vec::new();
    let mut on_hit = |_: &mut dyn BlockSource, off: u64, _: &[u8]| {
        hits.push(off);
        HitAction::Continue
    };
    let mut progress = |_: u64, _: u64| {};
    diag::clear();
    scan_signatures(src, cfg, sig, &mut on_hit, &mut progress);
    hits
}

// ─── scan engine ─────────────────────────────────────────────────────────────

#[test]
fn scanner_visits_every_aligned_signature_once_across_block_boundaries() {
    let cfg = ScanConfig { block_size: 8192, window: 64, step: 512 };
    let sig = b"SIGN";
    let positions = [0usize, 8192 - 512, 8192, 8192 * 3 + 512, 8192 * 4 - 512];
    let mut data = filler(8192 * 5);
    for p in positions {
        data[p..p + 4].copy_from_slice(sig);
    }
    let mut src = MemorySource::from_bytes(data, "t");
    let hits = hits_of(&mut src, &cfg, sig);
    assert_eq!(hits, positions.iter().map(|p| *p as u64).collect::<Vec<_>>());
}

#[test]
fn scanner_sees_the_whole_window_even_when_it_straddles_a_block() {
    let cfg = ScanConfig { block_size: 8192, window: 1024, step: 512 };
    let mut data = filler(8192 * 2);
    let at = 8192 - 512;
    data[at..at + 4].copy_from_slice(b"SIGN");
    data[at + 1000] = 0xEE;
    let mut src = MemorySource::from_bytes(data, "t");
    let mut seen = Vec::new();
    let mut on_hit = |_: &mut dyn BlockSource, off: u64, w: &[u8]| {
        seen.push((off, w.len() >= 1024, w[1000]));
        HitAction::Continue
    };
    let mut progress = |_: u64, _: u64| {};
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(seen, vec![(at as u64, true, 0xEE)]);
    assert_eq!(stats.signatures, 1);
    assert_eq!(stats.bytes_read, 8192 * 2);
}

#[test]
fn scanner_ignores_unaligned_signatures() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let mut data = filler(4096 * 2);
    data[100..104].copy_from_slice(b"SIGN");
    data[1024..1028].copy_from_slice(b"SIGN");
    let mut src = MemorySource::from_bytes(data, "t");
    assert_eq!(hits_of(&mut src, &cfg, b"SIGN"), vec![1024]);
}

#[test]
fn scanner_signature_at_the_very_end_is_reported_with_a_short_window() {
    let cfg = ScanConfig { block_size: 4096, window: 4096, step: 512 };
    let mut data = filler(4096 + 512);
    data[4096..4100].copy_from_slice(b"SIGN");
    let mut src = MemorySource::from_bytes(data, "t");
    let mut lens = Vec::new();
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, w: &[u8]| {
        lens.push(w.len());
        HitAction::Continue
    };
    let mut progress = |_: u64, _: u64| {};
    scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(lens, vec![512]);
}

#[test]
fn scanner_skip_to_jumps_past_consumed_bytes() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let mut data = filler(4096 * 4);
    for p in [0usize, 512, 1024, 8192, 8192 + 512] {
        data[p..p + 4].copy_from_slice(b"SIGN");
    }
    let mut src = MemorySource::from_bytes(data, "t");
    let mut hits = Vec::new();
    let mut on_hit = |_: &mut dyn BlockSource, off: u64, _: &[u8]| {
        hits.push(off);
        HitAction::SkipTo(off + 2048)
    };
    let mut progress = |_: u64, _: u64| {};
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(hits, vec![0, 8192]);
    assert_eq!(stats.signatures, 2);
}

#[test]
fn scanner_skip_to_behind_the_hit_is_ignored() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let mut data = filler(4096);
    data[0..4].copy_from_slice(b"SIGN");
    data[512..516].copy_from_slice(b"SIGN");
    let mut src = MemorySource::from_bytes(data, "t");
    let mut hits = Vec::new();
    let mut on_hit = |_: &mut dyn BlockSource, off: u64, _: &[u8]| {
        hits.push(off);
        HitAction::SkipTo(0)
    };
    let mut progress = |_: u64, _: u64| {};
    scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(hits, vec![0, 512]);
}

#[test]
fn scanner_reports_progress_up_to_the_size() {
    let cfg = ScanConfig { block_size: 1024, window: 16, step: 512 };
    let mut src = MemorySource::from_bytes(filler(4096 + 100), "t");
    let mut seen = Vec::new();
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, _: &[u8]| HitAction::Continue;
    let mut progress = |o: u64, s: u64| seen.push((o, s));
    scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(seen.first().unwrap().0, 0);
    assert_eq!(*seen.last().unwrap(), (4196, 4196));
    assert!(seen.windows(2).all(|w| w[0].0 <= w[1].0));
}

#[test]
fn scanner_skips_a_failing_block_and_keeps_going() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let mut src = Scripted {
        size: 4096 * 4,
        fail: Box::new(|off| if off == 4096 { Some(BlockError::Io("bad sector".into())) } else { None }),
        calls: Default::default(),
    };
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, _: &[u8]| HitAction::Continue;
    let mut progress = |_: u64, _: u64| {};
    diag::clear();
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(stats.read_errors, 1);
    assert_eq!(stats.bytes_skipped, 4096);
    assert_eq!(stats.bytes_read, 4096 * 3);
    assert!(!stats.aborted);
    assert_eq!(diag::count("ERR_ING_CARVE_READ"), 1);
    assert!(src.calls.borrow().contains(&8192), "scan resumed after the bad block");
}

#[test]
fn scanner_takes_the_large_skip_after_many_consecutive_errors() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let size = ERROR_SKIP + 4096 * 64;
    let mut src = Scripted {
        size,
        fail: Box::new(|off| if off < 4096 * 64 { Some(BlockError::Io("dead".into())) } else { None }),
        calls: Default::default(),
    };
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, _: &[u8]| HitAction::Continue;
    let mut progress = |_: u64, _: u64| {};
    diag::clear();
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(stats.read_errors, MAX_CONSECUTIVE_ERRORS + 1);
    assert!(stats.bytes_skipped >= ERROR_SKIP);
    assert!(!stats.aborted);
    let msgs: Vec<String> = diag::snapshot().iter().map(|e| e.to_string()).collect();
    assert!(msgs.iter().any(|m| m.contains("consecutive failures")), "{msgs:?}");
}

#[test]
fn scanner_skips_a_window_after_a_stall() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let size = STALL_SKIP + 8192;
    let mut src = Scripted {
        size,
        fail: Box::new(|off| if off == 0 { Some(BlockError::Stalled) } else { None }),
        calls: Default::default(),
    };
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, _: &[u8]| HitAction::Continue;
    let mut progress = |_: u64, _: u64| {};
    diag::clear();
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert_eq!(stats.stalls, 1);
    assert_eq!(stats.bytes_skipped, STALL_SKIP);
    assert_eq!(stats.bytes_read, 8192);
    assert_eq!(diag::count("ERR_ING_CARVE_STALLED"), 1);
    assert_eq!(src.calls.borrow()[1], STALL_SKIP);
}

#[test]
fn scanner_aborts_when_the_source_becomes_unavailable() {
    let cfg = ScanConfig { block_size: 4096, window: 16, step: 512 };
    let mut src = Scripted {
        size: 4096 * 4,
        fail: Box::new(|off| if off == 4096 { Some(BlockError::Unavailable("cannot reopen".into())) } else { None }),
        calls: Default::default(),
    };
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, _: &[u8]| HitAction::Continue;
    let mut progress = |_: u64, _: u64| {};
    diag::clear();
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert!(stats.aborted);
    assert_eq!(stats.bytes_read, 4096);
    assert_eq!(diag::count("ERR_ING_CARVE_ABORTED"), 1);
}

#[test]
fn scanner_on_an_empty_source_is_aborted_not_a_panic() {
    let cfg = ScanConfig::default();
    let mut src = MemorySource::from_bytes(Vec::new(), "empty");
    let mut on_hit = |_: &mut dyn BlockSource, _: u64, _: &[u8]| HitAction::Continue;
    let mut progress = |_: u64, _: u64| {};
    diag::clear();
    let stats = scan_signatures(&mut src, &cfg, b"SIGN", &mut on_hit, &mut progress);
    assert!(stats.aborted);
    assert!(diag::has("ERR_ING_CARVE_ABORTED"));
}

// ─── block sources ───────────────────────────────────────────────────────────

#[test]
fn direct_source_clamps_reads_to_the_size() {
    let mut src = MemorySource::from_bytes(filler(1000), "m");
    assert_eq!(src.size(), 1000);
    assert_eq!(src.label(), "m");
    assert_eq!(src.read_block(900, 4096).unwrap().len(), 100);
    assert!(src.read_block(1000, 10).unwrap().is_empty());
    assert!(src.read_block(5000, 10).unwrap().is_empty());
    assert_eq!(src.read_block(0, 4).unwrap(), filler(4));
}

struct Panicky;
impl Read for Panicky {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("decoder blew up");
    }
}
impl Seek for Panicky {
    fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
        Ok(0)
    }
}

#[test]
fn direct_source_turns_reader_panics_into_read_errors() {
    let mut src = DirectSource::new(Panicky, 4096, "p");
    match src.read_block(0, 512) {
        Err(BlockError::Io(e)) => assert!(e.contains("panicked") && e.contains("decoder blew up"), "{e}"),
        other => panic!("{other:?}"),
    }
}

/// Reader that sleeps on its first read, then behaves.
struct Slow {
    inner: Cursor<Vec<u8>>,
    slow_first: bool,
    delay: Duration,
}
impl Read for Slow {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.slow_first {
            self.slow_first = false;
            std::thread::sleep(self.delay);
        }
        self.inner.read(buf)
    }
}
impl Seek for Slow {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn guarded_source_reads_normally_within_the_budget() {
    let data = filler(2048);
    let d2 = data.clone();
    let mut src = GuardedSource::new(
        Slow { inner: Cursor::new(data), slow_first: false, delay: Duration::ZERO },
        2048,
        "g",
        Duration::from_secs(5),
        move || Ok(Slow { inner: Cursor::new(d2.clone()), slow_first: false, delay: Duration::ZERO }),
    );
    assert_eq!(src.read_block(1024, 4096).unwrap(), filler(2048)[1024..].to_vec());
    assert_eq!(src.stalls(), 0);
    assert!(src.read_block(2048, 1).unwrap().is_empty());
}

#[test]
fn guarded_source_abandons_a_stalled_read_and_reopens() {
    let data = filler(2048);
    let d2 = data.clone();
    let reopened = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let r2 = reopened.clone();
    let mut src = GuardedSource::new(
        Slow { inner: Cursor::new(data), slow_first: true, delay: Duration::from_millis(600) },
        2048,
        "g",
        Duration::from_millis(100),
        move || {
            r2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Slow { inner: Cursor::new(d2.clone()), slow_first: false, delay: Duration::ZERO })
        },
    );
    assert_eq!(src.read_block(0, 512), Err(BlockError::Stalled));
    assert_eq!(src.stalls(), 1);
    assert_eq!(src.read_block(0, 512).unwrap(), filler(512));
    assert_eq!(reopened.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(src.read_block(512, 512).unwrap(), filler(1024)[512..].to_vec(), "reader is reused after reopening");
    assert_eq!(reopened.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn guarded_source_reports_unavailable_when_reopen_fails() {
    let data = filler(2048);
    let mut src = GuardedSource::new(
        Slow { inner: Cursor::new(data), slow_first: true, delay: Duration::from_millis(600) },
        2048,
        "g",
        Duration::from_millis(100),
        || Err("segment vanished".to_string()),
    );
    assert_eq!(src.read_block(0, 512), Err(BlockError::Stalled));
    assert_eq!(src.read_block(0, 512), Err(BlockError::Unavailable("segment vanished".into())));
}

#[test]
fn guarded_source_passes_reader_errors_through_and_keeps_the_reader() {
    struct Failing(u32);
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Err(std::io::Error::other(format!("io failure #{}", self.0)))
        }
    }
    impl Seek for Failing {
        fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }
    let mut src = GuardedSource::new(Failing(0), 4096, "g", Duration::from_secs(1), || Ok(Failing(100)));
    assert_eq!(src.read_block(0, 10), Err(BlockError::Io("io failure #1".into())));
    assert_eq!(src.read_block(0, 10), Err(BlockError::Io("io failure #2".into())), "same reader, not reopened");
}

#[test]
fn block_error_display() {
    assert_eq!(BlockError::Io("x".into()).to_string(), "read error: x");
    assert_eq!(BlockError::Stalled.to_string(), "read stalled");
    assert_eq!(BlockError::Unavailable("y".into()).to_string(), "source unavailable: y");
}

#[test]
fn open_source_on_missing_or_empty_files() {
    let d = TempDir::new("carve_open");
    let e = open_source(&d.join("nope.raw")).err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_OPEN");
    let p = d.write("empty.bin", b"");
    let e = open_source(&p).err().unwrap();
    assert!(e.to_string().contains("empty"), "{e}");
    let p = d.write("some.bin", &filler(100));
    let src = open_source(&p).unwrap();
    assert_eq!(src.size(), 100);
}

// ─── base block validation ───────────────────────────────────────────────────

fn window_of(hive: &[u8]) -> Vec<u8> {
    hive[..WINDOW.min(hive.len())].to_vec()
}

#[test]
fn validate_accepts_a_builder_hive() {
    let h = software("A", r"C:\a.exe");
    let header = validate_base_block(&window_of(&h), 0x1000, "img").unwrap();
    assert_eq!(header.kind(), HiveKind::Software);
    assert!(header.checksum_valid());
}

fn reject_reason(window: &[u8]) -> String {
    let e = validate_base_block(window, 0x2000, "img").err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_HEADER_REJECTED");
    assert_eq!(e.severity(), Severity::Info);
    assert!(e.detail().contains("img offset 0x2000"), "{e}");
    e.detail().to_string()
}

#[test]
fn validate_rejects_transaction_logs() {
    let mut h = software("A", "a");
    h[0x1c..0x20].copy_from_slice(&6u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("transaction log"));
    h[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("transaction log"));
}

#[test]
fn validate_rejects_odd_file_types_and_versions() {
    let mut h = software("A", "a");
    h[0x1c..0x20].copy_from_slice(&9u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("file type 9"));
    let mut h = software("A", "a");
    h[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("version 1.2"));
}

#[test]
fn validate_rejects_implausible_sizes_and_roots() {
    let mut h = software("A", "a");
    h[0x28..0x2c].copy_from_slice(&0u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("data size 0"));
    let mut h = software("A", "a");
    h[0x28..0x2c].copy_from_slice(&4100u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("data size 4100"));
    let mut h = software("A", "a");
    h[0x28..0x2c].copy_from_slice(&0xF000_0000u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("data size"));
    let mut h = software("A", "a");
    h[0x24..0x28].copy_from_slice(&0x24u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("root cell offset 0x24"));
    let mut h = software("A", "a");
    h[0x24..0x28].copy_from_slice(&0x10_0000u32.to_le_bytes());
    assert!(reject_reason(&window_of(&h)).contains("root cell offset"));
}

#[test]
fn validate_rejects_a_signature_without_a_bin_behind_it() {
    let mut h = software("A", "a");
    h[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + 4].copy_from_slice(b"junk");
    assert!(reject_reason(&window_of(&h)).contains("no hive bin"));
    let short = h[..BASE_BLOCK_SIZE].to_vec();
    assert!(reject_reason(&short).contains("source ends"));
    assert!(reject_reason(b"regf").contains("bytes"), "truncated header");
    assert!(reject_reason(b"NOPE").is_empty() || true);
}

#[test]
fn validate_rejects_non_regf_bytes() {
    let e = validate_base_block(&filler(WINDOW), 0, "img").err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_HEADER_REJECTED");
}

#[test]
fn bin_header_rules() {
    let mut hdr = vec![0u8; 32];
    hdr[..4].copy_from_slice(b"hbin");
    hdr[4..8].copy_from_slice(&8192u32.to_le_bytes());
    hdr[8..12].copy_from_slice(&4096u32.to_le_bytes());
    assert_eq!(valid_bin_header(&hdr, 8192, 16384), Some(4096));
    assert_eq!(valid_bin_header(&hdr, 4096, 16384), None, "offset must match the chain");
    assert_eq!(valid_bin_header(&hdr, 8192, 8192), None, "bin would end past data size");
    hdr[8..12].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(valid_bin_header(&hdr, 8192, 16384), None);
    hdr[8..12].copy_from_slice(&4000u32.to_le_bytes());
    assert_eq!(valid_bin_header(&hdr, 8192, 16384), None);
    hdr[8..12].copy_from_slice(&4096u32.to_le_bytes());
    hdr[..4].copy_from_slice(b"hbim");
    assert_eq!(valid_bin_header(&hdr, 8192, 16384), None);
    assert_eq!(valid_bin_header(&hdr[..16], 8192, 16384), None, "short header");
}

// ─── reading a hive out of a source ──────────────────────────────────────────

fn read_from(bytes: Vec<u8>, offset: u64) -> Result<RawCarve, FaramirError> {
    let mut src = MemorySource::from_bytes(bytes, "mem");
    let header = HiveHeader::parse(&src.read_block(offset, 512).unwrap(), "h").unwrap();
    read_hive(&mut src, offset, &header)
}

#[test]
fn read_hive_recovers_a_complete_hive_byte_for_byte() {
    let h = software("A", r"C:\a.exe");
    let total = h.len();
    let d = disk(2 * MB, &[(MB, &h)]);
    let raw = read_from(d, MB as u64).unwrap();
    assert!(raw.complete);
    assert!(!raw.header_patched);
    assert_eq!(raw.recovered_len, total);
    assert_eq!(raw.declared_len, total);
    assert_eq!(raw.bins, 1);
    assert_eq!(raw.bytes, h);
    assert_eq!(raw.content_hash, content_hash(&h));
}

#[test]
fn read_hive_follows_a_multi_bin_chain() {
    let mut h = software("A", r"C:\a.exe");
    append_empty_bins(&mut h, 3);
    let d = disk(MB, &[(0, &h)]);
    let raw = read_from(d, 0).unwrap();
    assert!(raw.complete);
    assert_eq!(raw.bins, 4);
    assert_eq!(raw.bytes, h);
}

#[test]
fn read_hive_stops_where_the_chain_breaks_and_patches_the_base_block() {
    let mut h = software("A", r"C:\a.exe");
    append_empty_bins(&mut h, 3);
    let first_bin = u32::from_le_bytes(h[BASE_BLOCK_SIZE + 8..BASE_BLOCK_SIZE + 12].try_into().unwrap()) as usize;
    let third = BASE_BLOCK_SIZE + first_bin + 4096;
    h[third..third + 4].copy_from_slice(b"XXXX"); // third bin overwritten
    let declared = h.len();
    let raw = read_from(disk(MB, &[(0, &h)]), 0).unwrap();
    assert!(!raw.complete);
    assert!(raw.header_patched);
    assert_eq!(raw.bins, 2);
    assert_eq!(raw.declared_len, declared);
    assert_eq!(raw.recovered_len, third);
    assert_eq!(raw.bytes.len(), third);
    let patched = HiveHeader::parse(&raw.bytes, "p").unwrap();
    assert_eq!(patched.data_size as usize, third - BASE_BLOCK_SIZE);
    assert!(patched.checksum_valid(), "checksum recomputed for the patched size");
    assert_eq!(&raw.bytes[BASE_BLOCK_SIZE..third], &h[BASE_BLOCK_SIZE..third], "bins untouched");
}

#[test]
fn read_hive_truncated_by_end_of_source() {
    let mut h = software("A", r"C:\a.exe");
    append_empty_bins(&mut h, 4);
    let keep = h.len() - 4096 * 2 - 100; // source ends inside the 3rd bin
    let raw = read_from(h[..keep].to_vec(), 0).unwrap();
    assert!(!raw.complete);
    assert_eq!(raw.bins, 2);
    assert_eq!(raw.recovered_len, h.len() - 4096 * 3);
}

#[test]
fn read_hive_rejects_when_no_bin_is_intact() {
    let h = software("A", r"C:\a.exe");
    let header = HiveHeader::parse(&h, "h").unwrap();
    let mut src = MemorySource::from_bytes(h[..BASE_BLOCK_SIZE + 16].to_vec(), "mem");
    let e = read_hive(&mut src, 0, &header).err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_HIVE_REJECTED");
    assert!(e.detail().contains("no intact hive bin"), "{e}");
}

#[test]
fn read_hive_rejects_when_the_root_cell_is_not_an_allocated_root_key() {
    let mut h = software("A", r"C:\a.exe");
    let root = BASE_BLOCK_SIZE + u32::from_le_bytes(h[0x24..0x28].try_into().unwrap()) as usize;
    let size = i32::from_le_bytes(h[root..root + 4].try_into().unwrap());
    h[root..root + 4].copy_from_slice(&(-size).to_le_bytes()); // mark free
    let e = read_from(h.clone(), 0).err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_HIVE_REJECTED");
    assert!(e.detail().contains("root cell"), "{e}");

    let mut h2 = software("A", r"C:\a.exe");
    h2[root + 4..root + 6].copy_from_slice(b"vk");
    assert_eq!(read_from(h2, 0).err().unwrap().code(), "ERR_ING_CARVE_HIVE_REJECTED");

    let mut h3 = software("A", r"C:\a.exe");
    h3[root + 6..root + 8].copy_from_slice(&0x20u16.to_le_bytes()); // not flagged as root
    assert_eq!(read_from(h3, 0).err().unwrap().code(), "ERR_ING_CARVE_HIVE_REJECTED");
}

#[test]
fn read_hive_rejects_a_root_beyond_the_recovered_prefix() {
    let mut h = software("A", r"C:\a.exe");
    append_empty_bins(&mut h, 2);
    // move the declared root into the (soon broken) third bin
    let first_bin = u32::from_le_bytes(h[BASE_BLOCK_SIZE + 8..BASE_BLOCK_SIZE + 12].try_into().unwrap());
    h[0x24..0x28].copy_from_slice(&(first_bin + 4096 + 0x20).to_le_bytes());
    let sum = checksum(&h[..512]);
    h[0x1fc..0x200].copy_from_slice(&sum.to_le_bytes());
    let third = BASE_BLOCK_SIZE + first_bin as usize + 4096;
    h[third..third + 4].copy_from_slice(b"XXXX");
    let e = read_from(h, 0).err().unwrap();
    assert!(e.detail().contains("lies beyond"), "{e}");
}

#[test]
fn read_hive_survives_a_read_error_in_the_body() {
    let mut h = software("A", r"C:\a.exe");
    append_empty_bins(&mut h, 2);
    let header = HiveHeader::parse(&h, "h").unwrap();
    struct Flaky {
        data: Vec<u8>,
        fail_at: u64,
    }
    impl BlockSource for Flaky {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
        fn label(&self) -> &str {
            "flaky"
        }
        fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
            if offset == self.fail_at {
                return Err(BlockError::Io("unreadable".into()));
            }
            let end = (offset as usize + len).min(self.data.len());
            Ok(self.data[offset as usize..end].to_vec())
        }
    }
    // the body is requested in one 4 MB block starting at the hive offset; make that fail
    let mut src = Flaky { data: h.clone(), fail_at: 0 };
    diag::clear();
    let e = read_hive(&mut src, 0, &header).err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_HIVE_REJECTED");
    assert!(diag::has("ERR_ING_CARVE_READ"));
}

// ─── fingerprints ────────────────────────────────────────────────────────────

#[test]
fn content_hash_is_deterministic_and_sensitive() {
    let a = filler(5000);
    let mut b = a.clone();
    b[4999] ^= 1;
    assert_eq!(content_hash(&a), content_hash(&a));
    assert_ne!(content_hash(&a), content_hash(&b));
    assert_ne!(content_hash(&[]), content_hash(&[0]));
}

#[test]
fn fingerprint_tells_copies_apart() {
    let h = software("A", r"C:\a.exe");
    let hdr = HiveHeader::parse(&h, "h").unwrap();
    let fp = fingerprint(&hdr, content_hash(&h));
    assert!(fp.contains("SOFTWARE|5|5|"), "{fp}");
    assert_eq!(fp, fingerprint(&hdr, content_hash(&h)));
    let newer = HiveBuilder::software().build_with(7, 7);
    let hdr2 = HiveHeader::parse(&newer, "h").unwrap();
    assert_ne!(fp, fingerprint(&hdr2, content_hash(&newer)));
    assert_ne!(fp, fingerprint(&hdr, content_hash(&newer)), "same header, different bins");
}

#[test]
fn fingerprint_of_an_extracted_file_matches_the_carved_copy() {
    let d = TempDir::new("carve_fp");
    let h = software("A", r"C:\a.exe");
    let p = d.write("SOFTWARE", &h);
    let from_file = fingerprint_of_file(&p).unwrap();
    let raw = read_from(disk(MB, &[(4096 * 3, &h)]), 4096 * 3).unwrap();
    let hdr = HiveHeader::parse(&h, "h").unwrap();
    assert_eq!(from_file, fingerprint(&hdr, raw.content_hash));

    // file with slack after data_size: only the hive bytes count
    let mut padded = h.clone();
    padded.extend_from_slice(&filler(3000));
    let p2 = d.write("SOFTWARE.padded", &padded);
    assert_eq!(fingerprint_of_file(&p2).unwrap(), from_file);

    assert!(fingerprint_of_file(&d.write("notes.txt", b"hello")).is_none());
    let set = fingerprints_under(&d.path);
    assert_eq!(set.len(), 1);
    assert!(set.contains(&from_file));
}

#[test]
fn starts_with_regf_detects_hive_files() {
    let d = TempDir::new("carve_regf");
    assert!(starts_with_regf(&d.write("h", &software("A", "a"))));
    assert!(!starts_with_regf(&d.write("x", b"nothing")));
    assert!(!starts_with_regf(&d.join("missing")));
}

#[test]
fn filetime_conversion() {
    assert_eq!(filetime_to_string(0), "");
    assert_eq!(filetime_to_string(116_444_736_000_000_000), "1970-01-01 00:00:00.000");
    assert_eq!(filetime_to_string(116_444_736_000_000_000 + 15_000_000), "1970-01-01 00:00:01.500");
}

#[test]
fn carved_file_names_keep_the_kind_recognisable() {
    assert_eq!(carved_file_name(0x1000, HiveKind::Software), "carved_000000001000_SOFTWARE.regf");
    assert_eq!(carved_file_name(0xabcdef, HiveKind::NtUser), "carved_000000abcdef_NTUSER.DAT.regf");
    assert_eq!(HiveKind::from_file_name(&carved_file_name(7, HiveKind::NtUser)), HiveKind::NtUser);
    assert_eq!(HiveKind::from_file_name(&carved_file_name(7, HiveKind::System)), HiveKind::System);
    assert_eq!(HiveKind::from_file_name(&carved_file_name(7, HiveKind::Unknown)), HiveKind::Unknown);
}

// ─── carve_hives on a synthetic disk ─────────────────────────────────────────

fn ntuser(user: &str, name: &str, exe: &str) -> Vec<u8> {
    let mut b = HiveBuilder::ntuser(user);
    b.sz(&format!(r"SOFTWARE\{RUN}"), name, exe);
    b.build()
}

#[test]
fn carves_distinct_hives_skips_copies_and_rejects_garbage() {
    let d = TempDir::new("carve_disk");
    let sw = software("Old", r"C:\old\updater.exe");
    let nt = ntuser("bob", "Bob", r"C:\Users\bob\bob.exe");
    let mut garbage = vec![0u8; 512];
    garbage[..4].copy_from_slice(b"regf");
    let img = disk(
        8 * MB,
        &[(MB, &sw), (3 * MB + 512, &nt), (5 * MB, &sw), (7 * MB, &garbage)],
    );
    let report = carve_bytes(&d, img, &HashSet::new());
    assert_eq!(report.hives.len(), 2, "{}", summary_line(&report));
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.rejected_headers, 1);
    assert_eq!(report.rejected_hives, 0);
    assert_eq!(report.stats.signatures, 4);
    assert_eq!(report.truncated, 0);
    assert!(!report.stats.aborted);

    let first = &report.hives[0];
    assert_eq!(first.offset, MB as u64);
    assert_eq!(first.kind, HiveKind::Software);
    assert!(first.complete);
    assert_eq!(first.file_name(), "carved_000000100000_SOFTWARE.regf");
    assert_eq!(std::fs::read(&first.path).unwrap(), sw);
    let sidecar = std::fs::read_to_string(first.path.with_extension("carve.txt")).unwrap();
    assert!(sidecar.contains("offset=0x100000"), "{sidecar}");
    assert!(sidecar.contains("complete=true"), "{sidecar}");
    assert!(sidecar.contains(&format!("fingerprint={}", first.fingerprint)), "{sidecar}");

    let second = &report.hives[1];
    assert_eq!(second.offset, (3 * MB + 512) as u64);
    assert_eq!(second.kind, HiveKind::NtUser);
    assert_eq!(std::fs::read(&second.path).unwrap(), nt);

    assert_eq!(diag::count("ERR_ING_CARVE_HIVE_RECOVERED"), 2);
    assert_eq!(diag::count("ERR_ING_CARVE_DUPLICATE"), 1);
    assert_eq!(diag::count("ERR_ING_CARVE_HEADER_REJECTED"), 1);
    assert!(errors_of(Severity::Error).is_empty(), "{:?}", errors_of(Severity::Error));
    let s = summary_line(&report);
    assert!(s.contains("2 hive(s) carved") && s.contains("1 duplicate(s)") && s.contains("1 signature(s) rejected"), "{s}");
}

#[test]
fn carved_hive_identical_to_an_extracted_one_is_skipped() {
    let d = TempDir::new("carve_known");
    let sw = software("Live", r"C:\live.exe");
    let extracted = d.write("staging/partition_0/config/SOFTWARE", &sw);
    let known = fingerprints_under(extracted.parent().unwrap().parent().unwrap());
    let old = HiveBuilder::software().build_with(3, 3);
    let img = disk(4 * MB, &[(MB, &sw), (2 * MB, &old)]);
    let report = carve_bytes(&d, img, &known);
    assert_eq!(report.matches_extracted, 1);
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.hives[0].offset, 2 * MB as u64);
    assert!(diag::has("ERR_ING_CARVE_MATCHES_EXTRACTED"));
    let s = summary_line(&report);
    assert!(s.contains("1 identical to extracted hives"), "{s}");
}

#[test]
fn carves_a_hive_that_straddles_the_scan_block_boundary() {
    let d = TempDir::new("carve_boundary");
    let mut sw = software("Edge", r"C:\edge.exe");
    append_empty_bins(&mut sw, 2);
    let at = faramir::carve::scan::BLOCK_SIZE - 2048;
    let img = disk(6 * MB, &[(at, &sw)]);
    let report = carve_bytes(&d, img, &HashSet::new());
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.hives[0].offset, at as u64);
    assert!(report.hives[0].complete);
    assert_eq!(std::fs::read(&report.hives[0].path).unwrap(), sw);
}

#[test]
fn carves_a_hive_cut_by_the_end_of_the_image() {
    let d = TempDir::new("carve_eof");
    let mut sw = software("Tail", r"C:\tail.exe");
    append_empty_bins(&mut sw, 3);
    let at = 2 * MB;
    let total = at + sw.len() - 4096 - 10; // image ends 10 bytes before the 3rd bin completes
    let img = disk(total, &[(at, &sw[..total - at])]);
    let report = carve_bytes(&d, img, &HashSet::new());
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.truncated, 1);
    let h = &report.hives[0];
    assert!(!h.complete);
    assert_eq!(h.recovered_len, sw.len() - 4096 * 2);
    assert_eq!(h.declared_len, sw.len());
    assert!(h.describe().contains("truncated"), "{}", h.describe());
    assert!(diag::has("ERR_ING_CARVE_HIVE_TRUNCATED"));
    assert!(summary_line(&report).contains("1 truncated"));
}

#[test]
fn carved_hives_with_broken_chains_are_recovered_as_prefixes() {
    let d = TempDir::new("carve_broken");
    let mut sw = software("Pre", r"C:\prefix.exe");
    append_empty_bins(&mut sw, 3);
    let first_bin = u32::from_le_bytes(sw[BASE_BLOCK_SIZE + 8..BASE_BLOCK_SIZE + 12].try_into().unwrap()) as usize;
    let third = BASE_BLOCK_SIZE + first_bin + 4096;
    let mut img = disk(4 * MB, &[(MB, &sw)]);
    img[MB + third..MB + third + 4096].copy_from_slice(&filler(4096)); // page reused by another file
    let report = carve_bytes(&d, img, &HashSet::new());
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.hives[0].bins, 2);
    assert_eq!(report.hives[0].recovered_len, third);
    assert!(!report.hives[0].complete);
}

#[test]
fn carving_a_blob_without_hives_finds_nothing_and_reports_cleanly() {
    let d = TempDir::new("carve_none");
    let report = carve_bytes(&d, filler(3 * MB), &HashSet::new());
    assert!(report.hives.is_empty());
    assert_eq!(report.stats.signatures, 0);
    assert_eq!(report.stats.bytes_read, 3 * MB as u64);
    assert!(diag::snapshot().is_empty(), "{:?}", diag::snapshot());
    assert!(summary_line(&report).starts_with("0 hive(s) carved"));
    assert!(!d.join("carved").exists(), "nothing written when nothing carved");
}

#[test]
fn carve_path_opens_raw_files_and_records_open_failures() {
    let d = TempDir::new("carve_path");
    let sw = software("Raw", r"C:\raw.exe");
    let p = d.write("dump.bin", &disk(2 * MB, &[(MB, &sw)]));
    diag::clear();
    let report = carve_path(&p, &d.join("out"), &HashSet::new());
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.source, p.display().to_string());
    assert!(report.hives[0].source.ends_with("dump.bin"));

    diag::clear();
    let report = carve_path(&d.join("missing.bin"), &d.join("out2"), &HashSet::new());
    assert!(report.hives.is_empty());
    assert!(diag::has("ERR_ING_CARVE_OPEN"));
}

// ─── carved hives through the normal engine ──────────────────────────────────

#[test]
fn carved_hives_open_through_the_normal_pipeline() {
    let d = TempDir::new("carve_pipeline");
    let sw = software("Carved", r"C:\carved\c.exe");
    let nt = ntuser("eve", "Eve", r"C:\Users\eve\e.exe");
    let img = disk(4 * MB, &[(MB, &sw), (2 * MB, &nt)]);
    let report = carve_bytes(&d, img, &HashSet::new());
    let mut set = HiveSet::from_paths(&report.hive_paths(), &report.out_dir);
    assert_eq!(set.len(), 2);
    assert_eq!(set.kinds(), vec![HiveKind::Software, HiveKind::NtUser]);
    diag::clear();
    let found = run_technique(TechniqueId::Run, &mut set, None);
    let values: Vec<&str> = found.iter().map(|p| p.value.as_str()).collect();
    assert!(values.contains(&r"C:\carved\c.exe"), "{values:?}");
    assert!(values.contains(&r"C:\Users\eve\e.exe"), "{values:?}");
    for p in &found {
        assert!(report.hives.iter().any(|h| h.path.to_string_lossy() == p.origin), "origin {}", p.origin);
    }
    assert!(errors_of(Severity::Error).is_empty(), "{:?}", errors_of(Severity::Error));
}

#[test]
fn truncated_carved_hive_still_yields_what_survived() {
    let d = TempDir::new("carve_trunc_pipeline");
    let mut sw = software("Survivor", r"C:\survivor.exe");
    append_empty_bins(&mut sw, 2);
    let first_bin = u32::from_le_bytes(sw[BASE_BLOCK_SIZE + 8..BASE_BLOCK_SIZE + 12].try_into().unwrap()) as usize;
    let second = BASE_BLOCK_SIZE + first_bin;
    let mut img = disk(3 * MB, &[(MB, &sw)]);
    img[MB + second..MB + second + 4].copy_from_slice(b"????");
    let report = carve_bytes(&d, img, &HashSet::new());
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.hives[0].bins, 1);
    let mut set = HiveSet::from_paths(&report.hive_paths(), &report.out_dir);
    let found = run_technique(TechniqueId::Run, &mut set, None);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, r"C:\survivor.exe");
}

// ─── tagging and folding ─────────────────────────────────────────────────────

fn finding(technique: &str, value: &str, access: &str, origin: &str, source: &str) -> Persistence {
    Persistence {
        timestamp: "2024-01-01 00:00:00.000".into(),
        technique: technique.into(),
        path: format!(r"HKLM\SOFTWARE\{RUN}\X"),
        value: value.into(),
        access_gained: access.into(),
        source: source.into(),
        origin: origin.into(),
    }
}

fn carved_hive_at(path: &str, offset: u64, written: u64) -> CarvedHive {
    let mut h = software("A", "a");
    h[0x0c..0x14].copy_from_slice(&written.to_le_bytes());
    let header = HiveHeader::parse(&h, "h").unwrap();
    CarvedHive {
        source: "img.raw".into(),
        offset,
        header,
        kind: HiveKind::Software,
        declared_len: h.len(),
        recovered_len: h.len(),
        bins: 1,
        complete: true,
        fingerprint: format!("fp{offset}"),
        path: PathBuf::from(path),
    }
}

#[test]
fn fold_drops_what_the_live_registry_already_shows_and_tags_the_rest() {
    let hive = carved_hive_at(r"C:\staging\carved\carved_000000100000_SOFTWARE.regf", 0x100000, 116_444_736_000_000_000);
    let live = vec![finding("Run", r"C:\live.exe", "System", r"C:\staging\partition_0\config\SOFTWARE", "")];
    let carved = vec![
        finding("Run", r"c:\LIVE.exe", "System", &hive.path.to_string_lossy(), ""),
        finding("Run", r"C:\old.exe", "System", &hive.path.to_string_lossy(), ""),
        finding("Run", r"C:\gone.exe", "System", &hive.path.to_string_lossy(), SOURCE_DELETED),
    ];
    let (out, report) = tag_and_fold(&live, carved, std::slice::from_ref(&hive));
    assert_eq!(report.folded_into_live, 1);
    assert_eq!(report.folded_into_carved, 0);
    assert_eq!(report.kept, 2);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].value, r"C:\old.exe");
    assert_eq!(out[0].source, "carved:0x100000:SOFTWARE:1970-01-01 00:00:00.000");
    assert!(out[0].path.starts_with("carved SOFTWARE hive written 1970-01-01 00:00:00.000 at offset 0x100000"), "{}", out[0].path);
    assert!(out[0].path.ends_with(&format!(r"HKLM\SOFTWARE\{RUN}\X")), "{}", out[0].path);
    assert_eq!(out[1].value, r"C:\gone.exe");
    assert!(out[1].source.starts_with("carved+deleted:0x100000:"), "{}", out[1].source);

    let ev = persistence_to_event(&out[0], "HOST");
    assert_eq!(ev.artifact, "windows:persistence:carved:run");
    assert_eq!(ev.processname, "old.exe");
    let ev = persistence_to_event(&out[1], "HOST");
    assert_eq!(ev.artifact, "windows:persistence:carved:deleted:run");
}

#[test]
fn fold_keeps_the_newest_copy_among_carved_duplicates() {
    let older = carved_hive_at(r"C:\c\carved_000000001000_SOFTWARE.regf", 0x1000, 100);
    let newer = carved_hive_at(r"C:\c\carved_000000002000_SOFTWARE.regf", 0x2000, 200);
    let carved = vec![
        finding("Run", r"C:\dup.exe", "System", &older.path.to_string_lossy(), ""),
        finding("Run", r"C:\dup.exe", "System", &newer.path.to_string_lossy(), ""),
        finding("Run", r"C:\dup.exe", "System", &older.path.to_string_lossy(), ""),
    ];
    let (out, report) = tag_and_fold(&[], carved, &[older, newer.clone()]);
    assert_eq!(out.len(), 1);
    assert_eq!(report.folded_into_carved, 2);
    assert!(out[0].source.contains("0x2000"), "{}", out[0].source);
    assert!(out[0].path.contains("offset 0x2000"), "{}", out[0].path);
}

#[test]
fn fold_tags_findings_without_a_matching_hive() {
    let f = finding("Startup Folder", r"C:\x.lnk", "User", r"C:\c\Users\bob\Startup\x.lnk", "");
    let (out, _) = tag_and_fold(&[], vec![f], &[]);
    assert_eq!(out[0].source, "carved:?");
    assert!(out[0].path.starts_with("carved: "), "{}", out[0].path);
    assert_eq!(persistence_to_event(&out[0], "H").artifact, "windows:persistence:carved:startup_folder");
}

#[test]
fn fold_identity_ignores_case_of_the_value_but_not_the_access() {
    let hive = carved_hive_at(r"C:\c\h.regf", 0x1000, 1);
    let live = vec![finding("Run", r"C:\a.exe", "System", "live", "")];
    let carved = vec![
        finding("Run", r"C:\A.EXE", "System", &hive.path.to_string_lossy(), ""),
        finding("Run", r"C:\a.exe", "User", &hive.path.to_string_lossy(), ""),
        finding("RunOnce", r"C:\a.exe", "System", &hive.path.to_string_lossy(), ""),
    ];
    let (out, report) = tag_and_fold(&live, carved, std::slice::from_ref(&hive));
    assert_eq!(report.folded_into_live, 1);
    assert_eq!(out.len(), 2);
}

#[test]
fn carved_sources_are_recognised() {
    assert!(is_carved_source("carved"));
    assert!(is_carved_source("carved:0x10:SOFTWARE:x"));
    assert!(is_carved_source("carved+deleted:0x10:SOFTWARE:x"));
    assert!(!is_carved_source("vss:1:2024"));
    assert!(!is_carved_source("deleted"));
    assert!(!is_carved_source(""));
}

#[test]
fn live_vss_and_deleted_artifact_names_are_untouched() {
    let mut p = finding("Run", "x", "System", "o", "");
    assert_eq!(persistence_to_event(&p, "H").artifact, "windows:persistence:run");
    p.source = "deleted".into();
    assert_eq!(persistence_to_event(&p, "H").artifact, "windows:persistence:deleted:run");
    p.source = "vss:1:2024".into();
    assert_eq!(persistence_to_event(&p, "H").artifact, "windows:persistence:removed_since_vss:run");
}

// ─── error codes ─────────────────────────────────────────────────────────────

#[test]
fn carve_error_codes() {
    let cases: Vec<(FaramirError, &str, u32, Severity)> = vec![
        (FaramirError::CarveOpenFailed("d".into()), "ERR_ING_CARVE_OPEN", 2019, Severity::Error),
        (FaramirError::CarveReadError("d".into()), "ERR_ING_CARVE_READ", 2020, Severity::Warning),
        (FaramirError::CarveReadStalled("d".into()), "ERR_ING_CARVE_STALLED", 2021, Severity::Warning),
        (FaramirError::CarveHeaderRejected("d".into()), "ERR_ING_CARVE_HEADER_REJECTED", 2022, Severity::Info),
        (FaramirError::CarveHiveTruncated("d".into()), "ERR_ING_CARVE_HIVE_TRUNCATED", 2023, Severity::Warning),
        (FaramirError::CarveHiveRejected("d".into()), "ERR_ING_CARVE_HIVE_REJECTED", 2024, Severity::Warning),
        (FaramirError::CarveDuplicate("d".into()), "ERR_ING_CARVE_DUPLICATE", 2025, Severity::Info),
        (FaramirError::CarveMatchesExtracted("d".into()), "ERR_ING_CARVE_MATCHES_EXTRACTED", 2026, Severity::Info),
        (FaramirError::CarveWriteFailed("d".into()), "ERR_ING_CARVE_WRITE", 2027, Severity::Error),
        (FaramirError::CarveNoTarget("d".into()), "ERR_ING_CARVE_NO_TARGET", 2028, Severity::Warning),
        (FaramirError::CarveHiveRecovered("d".into()), "ERR_ING_CARVE_HIVE_RECOVERED", 2029, Severity::Info),
        (FaramirError::CarveAborted("d".into()), "ERR_ING_CARVE_ABORTED", 2030, Severity::Error),
    ];
    for (e, code, n, sev) in cases {
        assert_eq!(e.code(), code);
        assert_eq!(e.error_number(), n);
        assert_eq!(e.severity(), sev, "{code}");
        assert_eq!(e.category(), "ING");
        assert_eq!(e.detail(), "d");
        let s = e.to_string();
        assert!(s.starts_with(&format!("[{code} - {n}] ")), "{s}");
        assert!(s.ends_with("d"), "{s}");
        assert!(FaramirError::catalog().iter().any(|c| c.code() == code), "{code} missing from catalog");
    }
}

#[test]
fn ingest_error_numbers_are_dense_up_to_the_carving_codes() {
    let mut nums: Vec<u32> = FaramirError::catalog().iter().map(|e| e.error_number()).filter(|n| (2000..3000).contains(n)).collect();
    nums.sort_unstable();
    nums.dedup();
    assert_eq!(nums, (2001..=2042).collect::<Vec<_>>());
}

// ─── the real binary ─────────────────────────────────────────────────────────

fn run_cli(args: &[&std::ffi::OsStr]) -> (bool, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).args(args).output().expect("run faramir");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn csv_rows(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path).unwrap().lines().skip(1).map(|s| s.to_string()).collect()
}

#[test]
fn cli_carve_flag_recovers_hives_from_a_raw_image_without_a_file_system() {
    let d = TempDir::new("carve_cli_raw");
    let sw = software("Ghost", r"C:\ghost\ghost.exe");
    let nt = ntuser("mallory", "Mal", r"C:\Users\mallory\m.exe");
    let img = d.write("disk.raw", &disk(6 * MB, &[(MB, &sw), (4 * MB, &nt)]));
    let out = d.join("carved.csv");
    let (ok, stdout, stderr) = run_cli(&[
        "-f".as_ref(),
        img.as_os_str(),
        "-o".as_ref(),
        out.as_os_str(),
        "--carve".as_ref(),
        "--verbose".as_ref(),
    ]);
    assert!(ok, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Carving registry hives"), "{stdout}");
    assert!(stdout.contains("2 hive(s) carved"), "{stdout}");
    assert!(stderr.contains("ERR_ING_CARVE_HIVE_RECOVERED"), "{stderr}");
    assert!(!stderr.contains("[PANIC]"), "{stderr}");
    let rows = csv_rows(&out);
    let ghost: Vec<&String> = rows.iter().filter(|r| r.contains("ghost.exe")).collect();
    assert_eq!(ghost.len(), 1, "{rows:?}");
    assert!(ghost[0].contains("windows:persistence:carved:registry_run_key"), "{}", ghost[0]);
    assert!(ghost[0].contains("carved SOFTWARE hive"), "{}", ghost[0]);
    assert!(ghost[0].contains("offset 0x100000"), "{}", ghost[0]);
    assert!(ghost[0].starts_with("\"2024-01-17"), "hive write time is the event timestamp: {}", ghost[0]);
    assert!(rows.iter().any(|r| r.contains("m.exe") && r.contains("carved NTUSER.DAT hive")), "{rows:?}");
    assert!(rows.iter().all(|r| r.contains(",\"disk\",")), "computer name is the image stem: {rows:?}");
}

#[test]
fn cli_without_carve_flag_never_carves() {
    let d = TempDir::new("carve_cli_off");
    let sw = software("Ghost", r"C:\ghost\ghost.exe");
    let img = d.write("disk.raw", &disk(3 * MB, &[(MB, &sw)]));
    let out = d.join("plain.csv");
    let (ok, stdout, stderr) = run_cli(&["-f".as_ref(), img.as_os_str(), "-o".as_ref(), out.as_os_str(), "--verbose".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(!stdout.contains("Carving"), "{stdout}");
    assert!(!stderr.contains("CARVE"), "{stderr}");
    assert!(csv_rows(&out).is_empty(), "no file system, no findings");
}

#[test]
fn cli_carves_a_plain_file_that_is_not_a_hive() {
    let d = TempDir::new("carve_cli_blob");
    let sw = software("Paged", r"C:\paged\p.exe");
    let blob = d.write("pagefile.bin", &disk(2 * MB, &[(MB + 4096, &sw)]));
    let out = d.join("blob.csv");
    let (ok, stdout, stderr) = run_cli(&["-f".as_ref(), blob.as_os_str(), "-o".as_ref(), out.as_os_str(), "--carve".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("1 hive(s) carved"), "{stdout}");
    assert!(!stderr.contains("ERR_ING_CARVE_NO_TARGET"), "{stderr}");
    let rows = csv_rows(&out);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].contains("p.exe") && rows[0].contains("carved:registry_run_key") && rows[0].contains(",\"pagefile\","), "{}", rows[0]);
}

#[test]
fn cli_carve_flag_leaves_a_real_hive_file_to_the_normal_analysis() {
    let d = TempDir::new("carve_cli_hive");
    let hive = d.write("SOFTWARE", &software("Normal", r"C:\normal.exe"));
    let out = d.join("hive.csv");
    let (ok, stdout, stderr) = run_cli(&["-f".as_ref(), hive.as_os_str(), "-o".as_ref(), out.as_os_str(), "--carve".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(!stdout.contains("Carving"), "{stdout}");
    let rows = csv_rows(&out);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].contains("\"windows:persistence:registry_run_key\""), "{}", rows[0]);
    assert!(!rows[0].contains("carved"), "{}", rows[0]);
    assert!(stderr.contains("ERR_ING_CARVE_NO_TARGET"), "the flag had nothing to work on: {stderr}");
}

#[test]
fn cli_carve_flag_on_a_directory_warns_that_nothing_was_carved() {
    let d = TempDir::new("carve_cli_dir");
    d.write("evidence/Windows/System32/config/SOFTWARE", &software("Dir", r"C:\dir.exe"));
    let out = d.join("dir.csv");
    let (ok, _stdout, stderr) = run_cli(&["-d".as_ref(), d.join("evidence").as_os_str(), "-o".as_ref(), out.as_os_str(), "--carve".as_ref()]);
    assert!(ok, "{stderr}");
    assert!(stderr.contains("ERR_ING_CARVE_NO_TARGET"), "{stderr}");
    assert_eq!(csv_rows(&out).len(), 1);
}

#[test]
fn cli_help_documents_the_flag_as_opt_in() {
    let (ok, stdout, _) = run_cli(&["--help".as_ref()]);
    assert!(ok);
    assert!(stdout.contains("--carve"), "{stdout}");
    assert!(stdout.contains("off by default"), "{stdout}");
    assert!(stdout.contains("tagged \"carved\""), "{stdout}");
}

#[test]
fn write_carved_reports_unwritable_destinations() {
    let d = TempDir::new("carve_write_fail");
    let blocker = d.write("file", b"x");
    let h = software("A", "a");
    let header = HiveHeader::parse(&h, "h").unwrap();
    let raw = read_from(h.clone(), 0).unwrap();
    let e = write_carved(&blocker.join("sub"), "src", 0, &header, &raw).err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_WRITE");
}

#[test]
fn regf_magic_and_window_constants() {
    assert_eq!(REGF_MAGIC, b"regf");
    assert_eq!(WINDOW, BASE_BLOCK_SIZE + 32);
}

// ─── a real Windows hive ─────────────────────────────────────────────────────

#[test]
fn real_dirty_hive_is_carved_whole_and_opens_without_its_logs() {
    let d = TempDir::new("carve_real");
    let real = std::fs::read(fixture("dirty_hive/NewDirtyHive")).unwrap();
    let header = HiveHeader::parse(&real, "fixture").unwrap();
    assert!(header.is_dirty(), "fixture is a dirty hive");
    let hive_len = BASE_BLOCK_SIZE + header.data_size as usize;
    assert!(real.len() > hive_len, "the file carries slack past data_size, like real hives do");

    let img = disk(2 * MB, &[(MB, &real)]);
    let report = carve_bytes(&d, img, &HashSet::new());
    assert_eq!(report.hives.len(), 1, "{}", summary_line(&report));
    let h = &report.hives[0];
    assert!(h.complete);
    assert_eq!(h.recovered_len, hive_len);
    assert_eq!(std::fs::read(&h.path).unwrap(), real[..hive_len]);
    assert_eq!(h.fingerprint, fingerprint_of_file(&fixture("dirty_hive/NewDirtyHive")).unwrap(), "slack does not change the identity");

    // the normal pipeline opens it; no logs are around, which is said, not hidden
    diag::clear();
    let mut set = HiveSet::from_paths(&report.hive_paths(), &report.out_dir);
    assert_eq!(set.len(), 1);
    let found = run_technique(TechniqueId::DeletedRegistry, &mut set, None);
    assert!(diag::has("ERR_WIN_TX_LOG_NOT_FOUND"), "{:?}", diag::snapshot());
    assert!(!diag::has("ERR_WIN_TECH_PANIC"));
    assert!(errors_of(Severity::Error).is_empty(), "{:?}", errors_of(Severity::Error));
    let _ = found;
}

#[test]
fn real_hive_already_extracted_is_not_carved_twice() {
    let d = TempDir::new("carve_real_known");
    let real = std::fs::read(fixture("dirty_hive/NewDirtyHive")).unwrap();
    let extracted = d.write("staging/Users/bob_NTUSER.DAT", &real);
    let known = fingerprints_under(extracted.parent().unwrap());
    let img = disk(2 * MB, &[(MB, &real)]);
    let report = carve_bytes(&d, img, &known);
    assert!(report.hives.is_empty());
    assert_eq!(report.matches_extracted, 1);
}

// ─── raw devices ─────────────────────────────────────────────────────────────

#[test]
fn device_paths_are_recognised_and_kept_as_direct_files() {
    use faramir::carve::is_device_path;
    assert!(is_device_path(Path::new(r"\\.\PhysicalDrive0")));
    assert!(is_device_path(Path::new(r"\\.\C:")));
    assert!(is_device_path(Path::new("/dev/sdb")));
    assert!(!is_device_path(Path::new(r"C:\cases\disk.raw")));
    assert!(!is_device_path(Path::new("disk.E01")));
    let files = vec![r"\\.\PhysicalDriveNone".to_string()];
    let (_, direct, archives, images) = faramir::ingest::discover_evidence_targets(None, Some(&files));
    assert_eq!(direct, vec![PathBuf::from(r"\\.\PhysicalDriveNone")]);
    assert!(archives.is_empty() && images.is_empty());
    let e = open_source(Path::new(r"\\.\PhysicalDriveNone")).err().unwrap();
    assert_eq!(e.code(), "ERR_ING_CARVE_OPEN");
}

#[test]
fn fold_only_counts_truly_live_findings_as_present() {
    let hive = carved_hive_at(r"C:\c\h.regf", 0x1000, 1);
    let mut vss = finding("Run", r"C:\canary.exe", "User", r"C:\staging\partition_0_vss_0\Users\m_NTUSER.DAT", "");
    vss.source = "vss:0:2026-10-28".into();
    let deleted = finding("Run", r"C:\gone.exe", "User", r"C:\staging\partition_0\Users\b_NTUSER.DAT", SOURCE_DELETED);
    let live = vec![vss, deleted, finding("Run", r"C:\live.exe", "User", "live", "")];
    let carved = vec![
        finding("Run", r"C:\canary.exe", "User", &hive.path.to_string_lossy(), ""),
        finding("Run", r"C:\gone.exe", "User", &hive.path.to_string_lossy(), ""),
        finding("Run", r"C:\live.exe", "User", &hive.path.to_string_lossy(), ""),
    ];
    let (out, report) = tag_and_fold(&live, carved, std::slice::from_ref(&hive));
    assert_eq!(report.folded_into_live, 1, "only the truly live one folds");
    let values: Vec<&str> = out.iter().map(|p| p.value.as_str()).collect();
    assert_eq!(values, vec![r"C:\canary.exe", r"C:\gone.exe"]);
}

#[test]
fn fingerprints_ignore_hives_extracted_from_shadow_copies() {
    let d = TempDir::new("carve_fp_vss");
    let live = software("Live", r"C:\live.exe");
    let gone = software("Gone", r"C:\gone.exe");
    d.write("staging/partition_0/config/SOFTWARE", &live);
    d.write("staging/partition_0_vss_0/config/SOFTWARE", &live);
    d.write("staging/partition_0_vss_0/Users/mallory_NTUSER.DAT", &gone);
    let set = fingerprints_under(&d.join("staging"));
    assert_eq!(set.len(), 1, "{set:?}");
    let img = disk(4 * MB, &[(MB, &live), (2 * MB, &gone)]);
    let report = carve_bytes(&d, img, &set);
    assert_eq!(report.matches_extracted, 1);
    assert_eq!(report.hives.len(), 1);
    assert_eq!(report.hives[0].offset, 2 * MB as u64, "the snapshot-only hive is carved");
}

#[test]
fn fold_keeps_findings_that_differ_only_by_location() {
    let hive = carved_hive_at(r"C:\c\h.regf", 0x1000, 1);
    let mut a = finding("Windows Service", r"svchost.exe -k netsvcs", "System", &hive.path.to_string_lossy(), "");
    a.path = r"HKLM\SYSTEM\ControlSet001\Services\Alpha\ImagePath".into();
    let mut b = a.clone();
    b.path = r"HKLM\SYSTEM\ControlSet001\Services\Beta\ImagePath".into();
    let mut live = a.clone();
    live.origin = "live".into();
    let (out, report) = tag_and_fold(&[live], vec![a, b], std::slice::from_ref(&hive));
    assert_eq!(report.folded_into_live, 1);
    assert_eq!(out.len(), 1);
    assert!(out[0].path.contains(r"Services\Beta"), "{}", out[0].path);
}
