//! Whole-hive carving: validate a `regf` base block found in raw bytes, pull
//! the hive bins that follow it as long as the chain is intact, and write the
//! result as a file the normal pipeline can open.
//!
//! What makes this reliable: every hive bin carries its own offset relative
//! to the start of the bins region, so a contiguous hive verifies itself bin
//! by bin and the carve stops exactly where the chain breaks. The root key
//! cell is then checked before anything is accepted.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use super::scan::BLOCK_SIZE;
use super::source::BlockSource;
use crate::errors::FaramirError;
use crate::windows::diag;
use crate::windows::hives::{compute_base_block_checksum, read_hive_header, HiveHeader, HiveKind, BASE_BLOCK_SIZE};

pub const HBIN_HEADER: usize = 32;
pub const HBIN_MAGIC: &[u8; 4] = b"hbin";
pub const REGF_MAGIC: &[u8; 4] = b"regf";
/// Bytes the scanner must present after a `regf` signature: base block + first bin header.
pub const WINDOW: usize = BASE_BLOCK_SIZE + HBIN_HEADER;
/// Largest hive accepted (SOFTWARE on a long-lived server is a few hundred MB).
pub const MAX_HIVE_BYTES: u64 = 2 << 30;
/// Smallest key cell: size + nk fixed part.
const NK_FIXED: usize = 0x50;
const NK_ROOT_FLAG: u16 = 0x04;
const DATA_SIZE_OFFSET: usize = 0x28;
const CHECKSUM_OFFSET: usize = 0x1fc;

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Size of the bin whose 32-byte header is `hdr`, when it is sane:
/// `hbin` magic, offset equal to its position in the chain, non-zero size
/// in 4 KB units that stays inside the declared data size.
pub fn valid_bin_header(hdr: &[u8], expected_offset: u32, data_size: u32) -> Option<u32> {
    if hdr.len() < HBIN_HEADER || &hdr[..4] != HBIN_MAGIC {
        return None;
    }
    let offset = u32_at(hdr, 4);
    let size = u32_at(hdr, 8);
    if offset != expected_offset || size == 0 || !size.is_multiple_of(4096) {
        return None;
    }
    if (offset as u64) + (size as u64) > data_size as u64 {
        return None;
    }
    Some(size)
}

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

/// Bytes pulled out of the source for one hive, before being written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCarve {
    pub bytes: Vec<u8>,
    pub bins: usize,
    /// `4096 + data_size` as declared by the base block.
    pub declared_len: usize,
    /// Bytes kept: base block plus every bin verified in sequence.
    pub recovered_len: usize,
    pub complete: bool,
    /// The base block was rewritten (data size / checksum) to describe the recovered prefix.
    pub header_patched: bool,
    pub content_hash: u64,
}

/// FNV-1a 64 over `bytes`; cheap and good enough to tell two copies apart.
pub fn content_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Identity of a hive copy: header fields plus a hash of the bytes kept.
pub fn fingerprint(h: &HiveHeader, hash: u64) -> String {
    format!(
        "{}|{}|{}|{:016x}|{}|{:x}|{:08x}|{:016x}",
        h.embedded_name, h.primary_sequence, h.secondary_sequence, h.timestamp_filetime, h.data_size, h.root_cell_offset, h.checksum_stored, hash
    )
}

/// Read a hive whose base block sits at `offset`, following the bin chain
/// until it breaks or the declared size is reached.
pub fn read_hive(src: &mut dyn BlockSource, offset: u64, header: &HiveHeader) -> Result<RawCarve, FaramirError> {
    let label = src.label().to_string();
    let at = format!("{label} offset {offset:#x}");
    let data_size = header.data_size;
    let declared_len = BASE_BLOCK_SIZE + data_size as usize;
    let mut buf: Vec<u8> = Vec::with_capacity(declared_len.min(BLOCK_SIZE * 4));
    let mut validated: usize = 0; // bytes of bins verified
    let mut bins = 0usize;
    let mut broken = false;

    while buf.len() < declared_len && !broken {
        let want = BLOCK_SIZE.min(declared_len - buf.len());
        let chunk = match src.read_block(offset + buf.len() as u64, want) {
            Ok(c) if c.is_empty() => break,
            Ok(c) => c,
            Err(e) => {
                diag::record(FaramirError::CarveReadError(format!("{at}: {e} while reading hive body")));
                break;
            }
        };
        buf.extend_from_slice(&chunk);
        loop {
            let start = BASE_BLOCK_SIZE + validated;
            if start + HBIN_HEADER > buf.len() {
                break;
            }
            match valid_bin_header(&buf[start..start + HBIN_HEADER], validated as u32, data_size) {
                Some(size) => {
                    if start + size as usize > buf.len() {
                        // bin continues past what is buffered; read more
                        break;
                    }
                    validated += size as usize;
                    bins += 1;
                }
                None => {
                    broken = true;
                    break;
                }
            }
        }
    }

    if bins == 0 {
        return Err(FaramirError::CarveHiveRejected(format!("{at}: no intact hive bin after the base block")));
    }
    let recovered_len = BASE_BLOCK_SIZE + validated;
    buf.truncate(recovered_len);

    // the root key must be inside what was recovered and look like a root nk
    let root = header.root_cell_offset as usize;
    let cell = BASE_BLOCK_SIZE + root;
    if cell + 4 + NK_FIXED > recovered_len {
        return Err(FaramirError::CarveHiveRejected(format!(
            "{at}: root cell {:#x} lies beyond the {} recovered bytes",
            root, recovered_len
        )));
    }
    let cell_size = i32::from_le_bytes([buf[cell], buf[cell + 1], buf[cell + 2], buf[cell + 3]]);
    let nk = &buf[cell + 4..];
    if cell_size >= 0 || &nk[..2] != b"nk" || u16_at(nk, 2) & NK_ROOT_FLAG == 0 {
        return Err(FaramirError::CarveHiveRejected(format!(
            "{at}: root cell {:#x} is not an allocated root key",
            root
        )));
    }

    let complete = validated == data_size as usize;
    let mut header_patched = false;
    if !complete {
        buf[DATA_SIZE_OFFSET..DATA_SIZE_OFFSET + 4].copy_from_slice(&(validated as u32).to_le_bytes());
        let sum = compute_base_block_checksum(&buf[..512]);
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&sum.to_le_bytes());
        header_patched = true;
    }
    let hash = content_hash(&buf);
    Ok(RawCarve { bytes: buf, bins, declared_len, recovered_len, complete, header_patched, content_hash: hash })
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

/// Does this file start with a hive base block? (used to decide between
/// "analyse as a hive" and "carve as a raw blob" for `-f` inputs)
pub fn starts_with_regf(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == REGF_MAGIC
}
