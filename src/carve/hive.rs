//! Whole-hive carving: validate a `regf` base block found in raw bytes, pull
//! the hive bins that follow it as long as the chain is intact, and write the
//! result as a file the normal pipeline can open.
//!
//! The bin-chain reader lives in `blockcarve::hive` (every hive bin carries
//! its own offset relative to the start of the bins region, so a contiguous
//! hive verifies itself bin by bin and the carve stops exactly where the chain
//! breaks; the root key cell is then checked before anything is accepted).
//! This module keeps faramir's header type, its error codes and its sidecar.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

pub use blockcarve::hive::{starts_with_regf, valid_bin_header, RawCarve, HBIN_HEADER, HBIN_MAGIC, MAX_HIVE_BYTES, REGF_MAGIC, WINDOW};
use blockcarve::source::BlockSource;

use crate::errors::FaramirError;
use crate::windows::hives::{read_hive_header, HiveHeader, HiveKind, BASE_BLOCK_SIZE};

/// Smallest key cell: size + nk fixed part.
const NK_FIXED: usize = 0x50;

/// Decide whether the bytes at a `regf` signature are the base block of a
/// primary hive worth carving. `window` should hold [`WINDOW`] bytes unless
/// the source ends earlier.
pub fn validate_base_block(window: &[u8], offset: u64, label: &str) -> Result<HiveHeader, FaramirError> {
    let at = format!("{label} offset {offset:#x}");
    let reject = |why: String| FaramirError::CarveHeaderRejected(format!("{at}: {why}"));
    let header = HiveHeader::parse(window, &at).map_err(|e| reject(e.detail().to_string()))?;
    if header.is_transaction_log() {
        return Err(reject(format!("transaction log, not a primary hive (file type {})", header.file_type)));
    }
    if !header.is_primary() {
        return Err(reject(format!("unexpected file type {}", header.file_type)));
    }
    if !header.is_supported_version() {
        return Err(reject(format!("unsupported hive version {}", header.version())));
    }
    if header.data_size == 0 || !header.data_size.is_multiple_of(4096) || header.data_size as u64 > MAX_HIVE_BYTES {
        return Err(reject(format!("implausible data size {}", header.data_size)));
    }
    if !header.root_cell_offset.is_multiple_of(8) || header.root_cell_offset as u64 + NK_FIXED as u64 > header.data_size as u64 {
        return Err(reject(format!("implausible root cell offset {:#x}", header.root_cell_offset)));
    }
    if window.len() < WINDOW {
        return Err(reject(format!("source ends {} bytes after the signature, no bin can follow", window.len())));
    }
    if valid_bin_header(&window[BASE_BLOCK_SIZE..WINDOW], 0, header.data_size).is_none() {
        return Err(reject("no hive bin follows the base block".to_string()));
    }
    Ok(header)
}

/// FNV-1a 64 over `bytes`; cheap and good enough to tell two copies apart.
pub fn content_hash(bytes: &[u8]) -> u64 {
    blockcarve::content_hash(bytes)
}

/// Identity of a hive copy: header fields plus a hash of the bytes kept.
pub fn fingerprint(h: &HiveHeader, hash: u64) -> String {
    format!(
        "{}|{}|{}|{:016x}|{}|{:x}|{:016x}",
        h.embedded_name, h.primary_sequence, h.secondary_sequence, h.timestamp_filetime, h.data_size, h.root_cell_offset, hash
    )
}

/// The crate's view of a faramir header (the fields the bin-chain reader needs).
fn engine_header(h: &HiveHeader) -> blockcarve::hive::HiveHeader {
    blockcarve::hive::HiveHeader {
        primary_sequence: h.primary_sequence,
        secondary_sequence: h.secondary_sequence,
        timestamp_filetime: h.timestamp_filetime,
        major: h.major_version,
        minor: h.minor_version,
        file_type: h.file_type,
        root_cell_offset: h.root_cell_offset,
        data_size: h.data_size,
        embedded_name: h.embedded_name.clone(),
        checksum_stored: h.checksum_stored,
    }
}

/// Read a hive whose base block sits at `offset`, following the bin chain
/// until it breaks or the declared size is reached. The bytes are kept as
/// found (a dirty hive stays dirty and is reported as such); only a truncated
/// copy has its base block patched to the recovered size.
pub fn read_hive(src: &mut dyn BlockSource, offset: u64, header: &HiveHeader) -> Result<RawCarve, FaramirError> {
    let at = format!("{} offset {offset:#x}", src.label());
    let mut diagnosed = super::scan::Diagnosing::new(src);
    blockcarve::hive::read_hive_raw(&mut diagnosed, offset, &engine_header(header)).map_err(|e| FaramirError::CarveHiveRejected(format!("{at}: {e}")))
}

/// A hive written to the staging folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedHive {
    pub source: String,
    pub offset: u64,
    pub header: HiveHeader,
    pub kind: HiveKind,
    pub declared_len: usize,
    pub recovered_len: usize,
    pub bins: usize,
    pub complete: bool,
    pub fingerprint: String,
    pub path: PathBuf,
}

/// FILETIME to the timeline's date format.
pub fn filetime_to_string(ft: u64) -> String {
    if ft == 0 {
        return String::new();
    }
    let unix_100ns = ft as i64 - 116_444_736_000_000_000;
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .map(|dt| dt.format(crate::windows::techniques::FORMAT_DATE).to_string())
        .unwrap_or_default()
}

impl CarvedHive {
    pub fn written(&self) -> String {
        filetime_to_string(self.header.timestamp_filetime)
    }

    pub fn file_name(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
    }

    /// One-line description for logs and the finding path.
    pub fn describe(&self) -> String {
        let state = if self.complete { "complete" } else { "truncated" };
        let written = self.written();
        let written = if written.is_empty() { "unknown date".to_string() } else { written };
        format!(
            "{} hive written {} at offset {:#x} ({} bytes, {} bin(s), {})",
            self.kind, written, self.offset, self.recovered_len, self.bins, state
        )
    }
}

/// `carved_<offset>_<KIND>.regf`; the suffix keeps name classification in step with the header.
pub fn carved_file_name(offset: u64, kind: HiveKind) -> String {
    format!("carved_{offset:012x}_{}.regf", kind.label())
}

/// Write the carved bytes and a sidecar describing where they came from.
pub fn write_carved(out_dir: &Path, source: &str, offset: u64, header: &HiveHeader, raw: &RawCarve) -> Result<CarvedHive, FaramirError> {
    let kind = header.kind();
    std::fs::create_dir_all(out_dir)
        .map_err(|e| FaramirError::CarveWriteFailed(format!("{}: {e}", out_dir.display())))?;
    let path = out_dir.join(carved_file_name(offset, kind));
    std::fs::write(&path, &raw.bytes).map_err(|e| FaramirError::CarveWriteFailed(format!("{}: {e}", path.display())))?;
    let fp = fingerprint(header, raw.content_hash);
    let sidecar = path.with_extension("carve.txt");
    let _ = std::fs::write(
        &sidecar,
        format!(
            "source={source}\noffset={offset:#x}\nembedded_name={}\nkind={kind}\nprimary_sequence={}\nsecondary_sequence={}\nwritten={}\ndeclared_bytes={}\nrecovered_bytes={}\nbins={}\ncomplete={}\nheader_patched={}\nchecksum_valid={}\nfingerprint={fp}\n",
            header.embedded_name,
            header.primary_sequence,
            header.secondary_sequence,
            filetime_to_string(header.timestamp_filetime),
            raw.declared_len,
            raw.recovered_len,
            raw.bins,
            raw.complete,
            raw.header_patched,
            header.checksum_valid(),
        ),
    );
    Ok(CarvedHive {
        source: source.to_string(),
        offset,
        header: header.clone(),
        kind,
        declared_len: raw.declared_len,
        recovered_len: raw.recovered_len,
        bins: raw.bins,
        complete: raw.complete,
        fingerprint: fp,
        path,
    })
}

/// Fingerprint of a primary hive file on disk (first `4096 + data_size` bytes).
pub fn fingerprint_of_file(path: &Path) -> Option<String> {
    let header = read_hive_header(path).ok()?;
    if !header.is_primary() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let keep = bytes.len().min(BASE_BLOCK_SIZE + header.data_size as usize);
    Some(fingerprint(&header, content_hash(&bytes[..keep])))
}

/// Fingerprints of every primary hive under `dir` that the live file system
/// gave us, so the carver can tell a copy that only lives in unallocated
/// space from the live file seen twice. Hives extracted from a shadow copy
/// (`partition_<n>_vss_<m>` folders) are left out on purpose: a deleted hive
/// found both in a snapshot and in the raw bytes is two pieces of evidence.
pub fn fingerprints_under(dir: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    for entry in WalkDir::new(dir).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let in_snapshot = entry
            .path()
            .components()
            .any(|c| crate::windows::vss::parse_vss_dir_name(&c.as_os_str().to_string_lossy()).is_some());
        if in_snapshot {
            continue;
        }
        if let Some(fp) = fingerprint_of_file(entry.path()) {
            out.insert(fp);
        }
    }
    out
}
