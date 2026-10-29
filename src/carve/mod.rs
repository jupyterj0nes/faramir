//! Registry carving from raw bytes: disk images, pagefiles, memory dumps,
//! any blob. Opt-in (`--carve`), never part of the default run, and every
//! finding it produces is tagged `carved`.
//!
//! The scan engine, the guarded block sources and the hive-bin chain reader
//! come from the `blockcarve` crate shared with masstin, allymacb and caarea;
//! the registry side ([`hive`]) keeps faramir's header type, error codes and
//! sidecars.

pub mod fold;
pub mod hive;
pub mod scan;
pub use blockcarve::source;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

pub use fold::{is_carved_source, tag_and_fold, FoldReport, SOURCE_CARVED, SOURCE_CARVED_DELETED};
pub use hive::{fingerprints_under, CarvedHive};
pub use scan::ScanStats;
pub use blockcarve::source::{is_device_path, BlockSource, DirectSource, GuardedSource, MemorySource};

use crate::errors::FaramirError;
use crate::windows::diag;

/// Time budget for one block read on an EWF image before the reader is abandoned.
pub const EWF_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// What one carving pass produced.
#[derive(Debug, Default, Clone)]
pub struct CarveReport {
    pub source: String,
    pub out_dir: PathBuf,
    pub hives: Vec<CarvedHive>,
    pub stats: ScanStats,
    /// `regf` signatures that failed base-block validation.
    pub rejected_headers: usize,
    /// Valid base blocks without usable bins / root cell.
    pub rejected_hives: usize,
    pub duplicates: usize,
    pub matches_extracted: usize,
    pub truncated: usize,
}

impl CarveReport {
    pub fn hive_paths(&self) -> Vec<PathBuf> {
        self.hives.iter().map(|h| h.path.clone()).collect()
    }
}

/// Open a disk image or plain file as a block source, by extension. A raw
/// device (`\\.\PhysicalDrive0`, `/dev/sdb`) is read unbuffered so every
/// request stays sector aligned.
pub fn open_source(path: &Path) -> Result<Box<dyn BlockSource>, FaramirError> {
    let label = path.display().to_string();
    let lower = label.to_lowercase();
    let fail = |e: String| FaramirError::CarveOpenFailed(format!("{label}: {e}"));
    if lower.ends_with(".e01") || lower.ends_with(".ex01") {
        let reader = ewf::EwfReader::open(path).map_err(|e| fail(e.to_string()))?;
        let size = reader.total_size();
        let reopen_path = path.to_path_buf();
        let src = GuardedSource::new(reader, size, label.clone(), EWF_READ_TIMEOUT, move || {
            ewf::EwfReader::open(&reopen_path).map_err(|e| e.to_string())
        });
        return Ok(Box::new(src));
    }
    if lower.ends_with(".vmdk") {
        let reader = crate::ingest::vmdk::VmdkReader::open(&label).map_err(fail)?;
        let size = reader.total_size();
        return Ok(Box::new(DirectSource::new(reader, size, label)));
    }
    if lower.ends_with(".vhd") || lower.ends_with(".vhdx") {
        let (reader, size) = crate::ingest::vhd::open_virtual_disk(&label).map_err(fail)?;
        return Ok(Box::new(DirectSource::new(reader, size, label)));
    }
    blockcarve::source::open_file(path).map_err(FaramirError::CarveOpenFailed)
}

fn progress_bar(size: u64) -> ProgressBar {
    if diag::is_quiet() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(size);
    pb.set_style(
        ProgressStyle::with_template("  🔪 [{bar:30.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
    );
    pb
}

/// Scan `src` for primary hives and write every distinct one under `out_dir`.
/// `known` holds fingerprints of hives already obtained by other means
/// (file system, shadow copies); identical copies are reported and skipped.
pub fn carve_hives(src: &mut dyn BlockSource, out_dir: &Path, known: &HashSet<String>) -> CarveReport {
    let label = src.label().to_string();
    let mut report = CarveReport { source: label.clone(), out_dir: out_dir.to_path_buf(), ..Default::default() };
    let mut seen: HashSet<String> = HashSet::new();
    let pb = progress_bar(src.size());
    let cfg = scan::ScanConfig { window: hive::WINDOW, ..Default::default() };

    let mut hives: Vec<CarvedHive> = Vec::new();
    let mut rejected_headers = 0usize;
    let mut rejected_hives = 0usize;
    let mut duplicates = 0usize;
    let mut matches_extracted = 0usize;
    let mut truncated = 0usize;

    let mut on_hit = |src: &mut dyn BlockSource, offset: u64, window: &[u8]| -> scan::HitAction {
        let header = match hive::validate_base_block(window, offset, &label) {
            Ok(h) => h,
            Err(e) => {
                rejected_headers += 1;
                diag::record(e);
                return scan::HitAction::Continue;
            }
        };
        let raw = match hive::read_hive(src, offset, &header) {
            Ok(r) => r,
            Err(e) => {
                rejected_hives += 1;
                diag::record(e);
                return scan::HitAction::Continue;
            }
        };
        let resume = offset + raw.recovered_len as u64;
        let fp = hive::fingerprint(&header, raw.content_hash);
        let what = format!("{} at {offset:#x} ({} bytes)", header.kind(), raw.recovered_len);
        if known.contains(&fp) {
            matches_extracted += 1;
            diag::record(FaramirError::CarveMatchesExtracted(format!("{label}: {what}")));
            return scan::HitAction::SkipTo(resume);
        }
        if !seen.insert(fp) {
            duplicates += 1;
            diag::record(FaramirError::CarveDuplicate(format!("{label}: {what}")));
            return scan::HitAction::SkipTo(resume);
        }
        match hive::write_carved(out_dir, &label, offset, &header, &raw) {
            Ok(h) => {
                if !h.complete {
                    truncated += 1;
                    diag::record(FaramirError::CarveHiveTruncated(format!(
                        "{label}: {} declared {} bytes, {} recovered ({} bin(s))",
                        what, raw.declared_len, raw.recovered_len, raw.bins
                    )));
                }
                diag::record(FaramirError::CarveHiveRecovered(format!("{label}: {}", h.describe())));
                out!("\t[carved] {}", h.describe());
                pb.set_message(format!("{} hive(s)", hives.len() + 1));
                hives.push(h);
            }
            Err(e) => {
                diag::record(e);
            }
        }
        scan::HitAction::SkipTo(resume)
    };
    let mut on_progress = |offset: u64, _size: u64| pb.set_position(offset);

    let stats = scan::scan_signatures(src, &cfg, hive::REGF_MAGIC, &mut on_hit, &mut on_progress);
    pb.finish_and_clear();

    report.hives = hives;
    report.stats = stats;
    report.rejected_headers = rejected_headers;
    report.rejected_hives = rejected_hives;
    report.duplicates = duplicates;
    report.matches_extracted = matches_extracted;
    report.truncated = truncated;
    report.stats.stalls = report.stats.stalls.max(src.stalls());
    report
}

/// Open `path` and carve it. Errors opening the source are recorded and yield an empty report.
pub fn carve_path(path: &Path, out_dir: &Path, known: &HashSet<String>) -> CarveReport {
    match open_source(path) {
        Ok(mut src) => carve_hives(&mut *src, out_dir, known),
        Err(e) => {
            diag::record(e);
            CarveReport { source: path.display().to_string(), out_dir: out_dir.to_path_buf(), ..Default::default() }
        }
    }
}

/// Human summary line for the console.
pub fn summary_line(r: &CarveReport) -> String {
    let mut parts = vec![format!("{} hive(s) carved", r.hives.len())];
    if r.truncated > 0 {
        parts.push(format!("{} truncated", r.truncated));
    }
    if r.matches_extracted > 0 {
        parts.push(format!("{} identical to extracted hives", r.matches_extracted));
    }
    if r.duplicates > 0 {
        parts.push(format!("{} duplicate(s)", r.duplicates));
    }
    if r.rejected_headers > 0 || r.rejected_hives > 0 {
        parts.push(format!("{} signature(s) rejected", r.rejected_headers + r.rejected_hives));
    }
    if r.stats.read_errors > 0 || r.stats.stalls > 0 {
        parts.push(format!("{} read error(s), {} stall(s), {} MB skipped", r.stats.read_errors, r.stats.stalls, r.stats.bytes_skipped >> 20));
    }
    format!(
        "{} ({} MB scanned, {} regf signature(s))",
        parts.join(", "),
        r.stats.bytes_read >> 20,
        r.stats.signatures
    )
}
