//! Hive discovery, classification and opening.
//!
//! A hive is classified by *two* independent sources:
//!
//! 1. the file name (`SYSTEM`, `bob_NTUSER.DAT`, `C_Windows_System32_config_SOFTWARE`, …)
//! 2. the file name embedded in the regf base block (offset 0x30, UTF-16LE,
//!    last 32 characters of the original path, e.g. `emRoot\System32\Config\SOFTWARE`)
//!
//! The header wins when both are known. When neither is known the hive is
//! kept with [`HiveKind::Unknown`] and every technique tries all of its roots
//! against it, so a renamed hive never loses detections.

use std::fs::File;
use std::io::{BufReader, Read};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use nt_hive2::transactionlog::TransactionLog;
use nt_hive2::{CleanHive, ContainsHive, DirtyHive, Hive, HiveParseMode, Offset};
use walkdir::WalkDir;

use super::diag;
use super::txlog::{self, TxLogCandidate, TxLogSelection};
use crate::errors::FaramirError;

pub const BASE_BLOCK_SIZE: usize = 4096;
pub const REGF_MAGIC: &[u8; 4] = b"regf";
const EMBEDDED_NAME_OFFSET: usize = 0x30;
const EMBEDDED_NAME_BYTES: usize = 64;
const CHECKSUM_OFFSET: usize = 0x1fc;

/// Which well-known registry hive a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiveKind {
    System,
    Software,
    Sam,
    Security,
    Default,
    NtUser,
    UsrClass,
    Amcache,
    Bcd,
    Components,
    Drivers,
    Unknown,
}

impl HiveKind {
    pub const ALL: [HiveKind; 12] = [
        HiveKind::System,
        HiveKind::Software,
        HiveKind::Sam,
        HiveKind::Security,
        HiveKind::Default,
        HiveKind::NtUser,
        HiveKind::UsrClass,
        HiveKind::Amcache,
        HiveKind::Bcd,
        HiveKind::Components,
        HiveKind::Drivers,
        HiveKind::Unknown,
    ];

    /// Canonical on-disk file name (upper case) or `None` for `Unknown`.
    pub fn canonical_file_name(&self) -> Option<&'static str> {
        match self {
            HiveKind::System => Some("SYSTEM"),
            HiveKind::Software => Some("SOFTWARE"),
            HiveKind::Sam => Some("SAM"),
            HiveKind::Security => Some("SECURITY"),
            HiveKind::Default => Some("DEFAULT"),
            HiveKind::NtUser => Some("NTUSER.DAT"),
            HiveKind::UsrClass => Some("USRCLASS.DAT"),
            HiveKind::Amcache => Some("AMCACHE.HVE"),
            HiveKind::Bcd => Some("BCD"),
            HiveKind::Components => Some("COMPONENTS"),
            HiveKind::Drivers => Some("DRIVERS"),
            HiveKind::Unknown => None,
        }
    }

    pub fn label(&self) -> &'static str {
        self.canonical_file_name().unwrap_or("UNKNOWN")
    }

    /// `NTUSER.DAT` and `DEFAULT` share the HKCU layout (`SOFTWARE\…`, `Control Panel\…`).
    pub fn is_user_profile(&self) -> bool {
        matches!(self, HiveKind::NtUser | HiveKind::Default)
    }

    /// Hives that hold persistence-relevant data.
    pub fn is_persistence_relevant(&self) -> bool {
        matches!(
            self,
            HiveKind::System
                | HiveKind::Software
                | HiveKind::Default
                | HiveKind::NtUser
                | HiveKind::UsrClass
                | HiveKind::Unknown
        )
    }

    /// Tokens tried against file names, longest first so `NTUSER.DAT` wins over `DAT`.
    const NAME_TOKENS: [(&'static str, HiveKind); 11] = [
        ("USRCLASS.DAT", HiveKind::UsrClass),
        ("AMCACHE.HVE", HiveKind::Amcache),
        ("NTUSER.DAT", HiveKind::NtUser),
        ("COMPONENTS", HiveKind::Components),
        ("SECURITY", HiveKind::Security),
        ("SOFTWARE", HiveKind::Software),
        ("DEFAULT", HiveKind::Default),
        ("DRIVERS", HiveKind::Drivers),
        ("SYSTEM", HiveKind::System),
        ("SAM", HiveKind::Sam),
        ("BCD", HiveKind::Bcd),
    ];

    /// Suffixes collectors append to copied hives (`SOFTWARE.hve`, `SYSTEM.bak`, …).
    const EXTRA_SUFFIXES: [&'static str; 9] = [
        ".HVE", ".HIV", ".BAK", ".ORIG", ".COPY", ".BIN", ".REGF", ".RAW", ".OLD",
    ];

    fn matches_token(name: &str, token: &str) -> bool {
        name == token
            || name.ends_with(&format!("_{token}"))
            || name.ends_with(&format!("-{token}"))
            || name.ends_with(&format!(".{token}"))
    }

    fn strip_extra_suffixes(name: &str) -> String {
        let mut n = name.to_string();
        loop {
            let before = n.clone();
            for suf in Self::EXTRA_SUFFIXES {
                if n.len() > suf.len() && n.ends_with(suf) {
                    n.truncate(n.len() - suf.len());
                }
            }
            if n == before {
                return n;
            }
        }
    }

    /// Guess the hive kind from a file name alone (case-insensitive).
    ///
    /// Accepts canonical names, collector prefixes (`HOST_SYSTEM`, `bob-NTUSER.DAT`,
    /// `C_Windows_System32_config_SOFTWARE`) and copy suffixes (`SOFTWARE.hve`).
    pub fn from_file_name(name: &str) -> HiveKind {
        let n = name.trim().to_uppercase();
        if n.is_empty() {
            return HiveKind::Unknown;
        }
        for (tok, kind) in Self::NAME_TOKENS {
            if Self::matches_token(&n, tok) {
                return kind;
            }
        }
        let stripped = Self::strip_extra_suffixes(&n);
        if stripped != n {
            for (tok, kind) in Self::NAME_TOKENS {
                if Self::matches_token(&stripped, tok) {
                    return kind;
                }
            }
        }
        let last = stripped.rsplit(['_', '-']).next().unwrap_or(&stripped);
        if last.starts_with("NTUSER.") {
            return HiveKind::NtUser;
        }
        if last.starts_with("USRCLASS.") {
            return HiveKind::UsrClass;
        }
        HiveKind::Unknown
    }

    /// Classify from the path embedded in the base block (`emRoot\System32\Config\SOFTWARE`).
    pub fn from_embedded_name(embedded: &str) -> HiveKind {
        let trimmed = embedded.trim_matches(char::from(0)).trim();
        if trimmed.is_empty() {
            return HiveKind::Unknown;
        }
        let last = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed).to_uppercase();
        match last.as_str() {
            "SYSTEM" => HiveKind::System,
            "SOFTWARE" => HiveKind::Software,
            "SAM" => HiveKind::Sam,
            "SECURITY" => HiveKind::Security,
            "DEFAULT" => HiveKind::Default,
            "NTUSER.DAT" | "NTUSER.MAN" => HiveKind::NtUser,
            "USRCLASS.DAT" => HiveKind::UsrClass,
            "AMCACHE.HVE" => HiveKind::Amcache,
            "BCD" => HiveKind::Bcd,
            "COMPONENTS" => HiveKind::Components,
            "DRIVERS" => HiveKind::Drivers,
            _ => HiveKind::Unknown,
        }
    }
}

impl std::fmt::Display for HiveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Registry companion files that must never be parsed as primary hives.
pub fn is_hive_companion_file(name: &str) -> bool {
    let n = name.trim().to_uppercase();
    n.ends_with(".LOG")
        || n.ends_with(".LOG1")
        || n.ends_with(".LOG2")
        || n.ends_with(".BLF")
        || n.ends_with(".REGTRANS-MS")
        || n.ends_with(".TMP")
        || n.ends_with(".SAV")
        || n.ends_with(".TM")
        || n.contains(".TMCONTAINER")
        || n.contains(".TM.BLF")
}

/// For a companion file (`SYSTEM.LOG1`, `NTUSER.DAT{guid}.TM.blf`) tell which hive it belongs to.
pub fn companion_base_kind(name: &str) -> HiveKind {
    let n = name.trim().to_uppercase();
    let base = match n.find('{') {
        Some(pos) => n[..pos].to_string(),
        None => {
            let mut b = n.clone();
            for suf in [".LOG1", ".LOG2", ".LOG", ".BLF", ".REGTRANS-MS", ".TMP", ".SAV", ".TM"] {
                if b.ends_with(suf) {
                    b.truncate(b.len() - suf.len());
                    break;
                }
            }
            b
        }
    };
    HiveKind::from_file_name(&base)
}

/// Extensions that may hide a hive under an unusual name.
fn has_hive_like_extension(name: &str) -> bool {
    let n = name.to_uppercase();
    [".HVE", ".DAT", ".HIV", ".BAK", ".BIN", ".REGF", ".RAW", ".OLD", ".MAN"]
        .iter()
        .any(|s| n.ends_with(s))
}

/// Decoded regf base block (first 512 bytes are enough for logs, 4096 for primaries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveHeader {
    pub primary_sequence: u32,
    pub secondary_sequence: u32,
    pub timestamp_filetime: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub data_size: u32,
    pub embedded_name: String,
    pub checksum_stored: u32,
    pub checksum_calculated: u32,
}

/// XOR-32 over the first 508 bytes with the Windows corner cases.
pub fn compute_base_block_checksum(bytes: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..127 {
        let off = i * 4;
        if off + 4 > bytes.len() {
            break;
        }
        acc ^= u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
    match acc {
        0xffff_ffff => 0xffff_fffe,
        0 => 1,
        v => v,
    }
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn u64_at(bytes: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Decode the UTF-16LE name stored at offset 0x30 (stops at the first NUL).
pub fn decode_embedded_name(bytes: &[u8]) -> String {
    if bytes.len() < EMBEDDED_NAME_OFFSET + EMBEDDED_NAME_BYTES {
        return String::new();
    }
    let raw = &bytes[EMBEDDED_NAME_OFFSET..EMBEDDED_NAME_OFFSET + EMBEDDED_NAME_BYTES];
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

impl HiveHeader {
    /// Parse a base block. `label` is only used in error messages.
    pub fn parse(bytes: &[u8], label: &str) -> Result<HiveHeader, FaramirError> {
        if bytes.len() < 4 {
            return Err(FaramirError::HiveHeaderTruncated(format!(
                "{label} ({} bytes)",
                bytes.len()
            )));
        }
        if &bytes[..4] != REGF_MAGIC {
            return Err(FaramirError::HiveSignatureInvalid(format!(
                "{label} (found {:02x?})",
                &bytes[..4]
            )));
        }
        if bytes.len() < 512 {
            return Err(FaramirError::HiveHeaderTruncated(format!(
                "{label} ({} bytes, need at least 512)",
                bytes.len()
            )));
        }
        Ok(HiveHeader {
            primary_sequence: u32_at(bytes, 0x04),
            secondary_sequence: u32_at(bytes, 0x08),
            timestamp_filetime: u64_at(bytes, 0x0c),
            major_version: u32_at(bytes, 0x14),
            minor_version: u32_at(bytes, 0x18),
            file_type: u32_at(bytes, 0x1c),
            file_format: u32_at(bytes, 0x20),
            root_cell_offset: u32_at(bytes, 0x24),
            data_size: u32_at(bytes, 0x28),
            embedded_name: decode_embedded_name(bytes),
            checksum_stored: u32_at(bytes, CHECKSUM_OFFSET),
            checksum_calculated: compute_base_block_checksum(bytes),
        })
    }

    pub fn is_dirty(&self) -> bool {
        self.primary_sequence != self.secondary_sequence
    }

    pub fn checksum_valid(&self) -> bool {
        self.checksum_stored == self.checksum_calculated
    }

    pub fn is_primary(&self) -> bool {
        self.file_type == 0
    }

    /// Legacy (.LOG, Windows XP..8.0) formats.
    pub fn is_legacy_log(&self) -> bool {
        matches!(self.file_type, 1 | 2)
    }

    /// New (HvLE, Windows 8.1+) transaction log format.
    pub fn is_new_log(&self) -> bool {
        self.file_type == 6
    }

    pub fn is_transaction_log(&self) -> bool {
        self.is_legacy_log() || self.is_new_log()
    }

    pub fn kind(&self) -> HiveKind {
        HiveKind::from_embedded_name(&self.embedded_name)
    }

    /// Version string such as `1.5`.
    pub fn version(&self) -> String {
        format!("{}.{}", self.major_version, self.minor_version)
    }

    /// nt_hive2 only accepts major 1 and minor 3..=6.
    pub fn is_supported_version(&self) -> bool {
        self.major_version == 1 && (3..=6).contains(&self.minor_version)
    }
}

/// Read and decode the base block of a file.
pub fn read_hive_header(path: &Path) -> Result<HiveHeader, FaramirError> {
    let label = path.display().to_string();
    let meta = std::fs::metadata(path)
        .map_err(|e| FaramirError::HiveOpenFailed(format!("{label}: {e}")))?;
    if meta.len() == 0 {
        return Err(FaramirError::HiveEmptyFile(label));
    }
    let mut file =
        File::open(path).map_err(|e| FaramirError::HiveOpenFailed(format!("{label}: {e}")))?;
    let mut buf = vec![0u8; BASE_BLOCK_SIZE];
    let mut read = 0usize;
    while read < buf.len() {
        match file.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) => return Err(FaramirError::IoError(format!("{label}: {e}"))),
        }
    }
    buf.truncate(read);
    let header = HiveHeader::parse(&buf, &label)?;
    if header.is_primary() && read < BASE_BLOCK_SIZE {
        return Err(FaramirError::HiveHeaderTruncated(format!(
            "{label} ({read} bytes, primary hives need {BASE_BLOCK_SIZE})"
        )));
    }
    Ok(header)
}

/// A hive that is queued for analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveInfo {
    pub path: PathBuf,
    /// Final decision (header wins over name).
    pub kind: HiveKind,
    /// What the file name alone suggested.
    pub name_kind: HiveKind,
    pub header: HiveHeader,
    /// Root under which transaction logs may be searched.
    pub evidence_root: PathBuf,
}

impl HiveInfo {
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    pub fn is_dirty(&self) -> bool {
        self.header.is_dirty()
    }

    pub fn label(&self) -> String {
        format!("{} [{}]", self.path.display(), self.kind)
    }
}

/// Decide what a file is. Errors are recorded in the diagnostics sink.
pub fn classify_hive(path: &Path, evidence_root: &Path) -> Result<HiveInfo, FaramirError> {
    let label = path.display().to_string();
    let header = match read_hive_header(path) {
        Ok(h) => h,
        Err(e) => return Err(diag::record(e)),
    };
    if header.is_transaction_log() {
        return Err(diag::record(FaramirError::HiveNotPrimaryFile(format!(
            "{label} (file type {})",
            header.file_type
        ))));
    }
    if !header.is_primary() {
        return Err(diag::record(FaramirError::HiveCorrupt(format!(
            "{label} (unexpected file type {})",
            header.file_type
        ))));
    }
    if !header.is_supported_version() {
        return Err(diag::record(FaramirError::HiveCorrupt(format!(
            "{label} (unsupported hive version {})",
            header.version()
        ))));
    }
    let name_kind = HiveKind::from_file_name(
        &path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    );
    let header_kind = header.kind();
    let kind = match (header_kind, name_kind) {
        (HiveKind::Unknown, HiveKind::Unknown) => {
            diag::record(FaramirError::HiveKindUnresolved(label.clone()));
            HiveKind::Unknown
        }
        (HiveKind::Unknown, n) => n,
        (h, HiveKind::Unknown) => h,
        (h, n) if h == n => h,
        (h, n) => {
            diag::record(FaramirError::HiveNameHeaderMismatch(format!(
                "{label} (name says {n}, header says {h} via '{}')",
                header.embedded_name
            )));
            h
        }
    };
    Ok(HiveInfo {
        path: path.to_path_buf(),
        kind,
        name_kind,
        header,
        evidence_root: evidence_root.to_path_buf(),
    })
}

fn starts_with_regf(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == REGF_MAGIC
}

/// Walk `root` and return every primary hive found, classified.
///
/// Companion files (`.LOG1`, `.blf`, `.regtrans-ms`, …) are skipped, files
/// are only sniffed when their name or extension looks hive-like, and
/// everything that is not `regf` is ignored.
pub fn discover_hives(root: &Path) -> Vec<HiveInfo> {
    let mut hives: Vec<HiveInfo> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();

    if root.is_file() {
        if let Ok(info) = classify_hive(root, root.parent().unwrap_or(root)) {
            out!("\t{}", info.label());
            hives.push(info);
        }
        return hives;
    }

    for entry in WalkDir::new(root).into_iter() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                diag::record(FaramirError::HiveDiscoveryIoError(e.to_string()));
                continue;
            }
        };
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();

        if is_hive_companion_file(&name) {
            if companion_base_kind(&name) != HiveKind::Unknown {
                diag::record(FaramirError::HiveCompanionSkipped(path.display().to_string()));
            }
            continue;
        }

        let name_kind = HiveKind::from_file_name(&name);
        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let looks_like_hive = name_kind != HiveKind::Unknown
            || has_hive_like_extension(&name)
            || (!name.contains('.') && len >= 8192 && len % 4096 == 0);
        if !looks_like_hive {
            continue;
        }
        if !starts_with_regf(path) {
            if name_kind != HiveKind::Unknown && len > 0 {
                diag::record(FaramirError::HiveSignatureInvalid(path.display().to_string()));
            }
            continue;
        }

        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if seen.contains(&canonical) {
            diag::record(FaramirError::HiveDuplicateSkipped(path.display().to_string()));
            continue;
        }

        if let Ok(info) = classify_hive(path, root) {
            if !info.kind.is_persistence_relevant() {
                continue;
            }
            let dirty = if info.is_dirty() { " (dirty)" } else { "" };
            out!("\t{}{}", info.label(), dirty);
            seen.push(canonical);
            hives.push(info);
        }
    }
    hives
}

pub type HiveFile = Hive<BufReader<File>, CleanHive>;

/// What happened while opening a hive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub was_dirty: bool,
    pub log1: Option<PathBuf>,
    pub log2: Option<PathBuf>,
    pub logs_applied: bool,
    pub opened_without_base_block: bool,
}

pub struct OpenedHive {
    pub hive: HiveFile,
    pub recovery: RecoveryReport,
}

fn parse_hive_file(
    path: &Path,
    header: &HiveHeader,
) -> Result<Hive<BufReader<File>, DirtyHive>, FaramirError> {
    let label = path.display().to_string();
    let file = File::open(path).map_err(|e| FaramirError::HiveOpenFailed(format!("{label}: {e}")))?;
    let reader = BufReader::new(file);
    let mode = if header.checksum_valid() {
        HiveParseMode::NormalWithBaseBlock
    } else {
        HiveParseMode::Normal(Offset(header.root_cell_offset))
    };
    match catch_unwind(AssertUnwindSafe(|| Hive::new(reader, mode))) {
        Ok(Ok(h)) => Ok(h),
        Ok(Err(e)) => Err(FaramirError::HiveOpenFailed(format!("{label}: {e}"))),
        Err(p) => Err(FaramirError::HiveParsePanic(format!(
            "{label}: {}",
            diag::panic_message(&*p)
        ))),
    }
}

/// Load the selected logs and apply them. Consumes `hive`; on failure the caller re-opens.
fn apply_selection(
    hive: Hive<BufReader<File>, DirtyHive>,
    selection: &TxLogSelection,
) -> Result<(HiveFile, Vec<PathBuf>), FaramirError> {
    let mut loaded: Vec<(PathBuf, TransactionLog)> = Vec::new();
    for cand in selection.usable() {
        match txlog::load_transaction_log(cand) {
            Ok(log) => loaded.push((cand.path.clone(), log)),
            Err(e) => {
                diag::record(e);
            }
        }
    }
    if loaded.is_empty() {
        return Err(FaramirError::TxLogApplyFailed(
            "no transaction log could be loaded".to_string(),
        ));
    }
    let used: Vec<PathBuf> = loaded.iter().map(|(p, _)| p.clone()).collect();
    let mut iter = loaded.into_iter();
    let (_, first) = iter.next().expect("non-empty");
    let second = iter.next().map(|(_, l)| l);

    let result = catch_unwind(AssertUnwindSafe(move || -> Result<HiveFile, FaramirError> {
        let with_first = hive
            .with_transaction_log(first)
            .map_err(|e| FaramirError::TxLogApplyFailed(e.to_string()))?;
        match second {
            Some(l2) => {
                let with_both = with_first
                    .with_transaction_log(l2)
                    .map_err(|e| FaramirError::TxLogApplyFailed(e.to_string()))?;
                Ok(with_both.apply_logs())
            }
            None => Ok(with_first.apply_logs()),
        }
    }));
    match result {
        Ok(Ok(h)) => Ok((h, used)),
        Ok(Err(e)) => Err(e),
        Err(p) => Err(FaramirError::TxLogApplyPanic(diag::panic_message(&*p))),
    }
}

/// Open a hive, replaying its transaction logs when it is dirty.
///
/// Never silently drops a hive: every degraded path records a diagnostic and
/// the hive is still returned (in its dirty on-disk state) so techniques can
/// run against whatever is there.
pub fn open_hive(info: &HiveInfo) -> Result<OpenedHive, FaramirError> {
    let label = info.path.display().to_string();
    let header = &info.header;
    let mut report = RecoveryReport {
        was_dirty: header.is_dirty(),
        ..Default::default()
    };

    if !header.checksum_valid() {
        diag::record(FaramirError::HiveChecksumInvalid(format!(
            "{label} (stored 0x{:08x}, calculated 0x{:08x}); opening without base block, logs cannot be replayed",
            header.checksum_stored, header.checksum_calculated
        )));
        let hive = parse_hive_file(&info.path, header).map_err(diag::record)?;
        report.opened_without_base_block = true;
        return Ok(OpenedHive {
            hive: hive.treat_hive_as_clean(),
            recovery: report,
        });
    }

    let hive = parse_hive_file(&info.path, header).map_err(diag::record)?;
    if !header.is_dirty() {
        return Ok(OpenedHive {
            hive: hive.treat_hive_as_clean(),
            recovery: report,
        });
    }

    out!("\t  [!] Dirty hive detected, applying transaction logs...");

    if header.primary_sequence != header.secondary_sequence.wrapping_add(1) {
        diag::record(FaramirError::TxLogSequenceMismatch(format!(
            "{label} (primary {} vs secondary {}: difference greater than 1, logs cannot be replayed)",
            header.primary_sequence, header.secondary_sequence
        )));
        return Ok(OpenedHive {
            hive: hive.treat_hive_as_clean(),
            recovery: report,
        });
    }

    let selection = txlog::locate_transaction_logs(info);
    report.log1 = selection.log1.as_ref().map(|c| c.path.clone());
    report.log2 = selection.log2.as_ref().map(|c| c.path.clone());

    if selection.is_empty() {
        if selection.rejected.is_empty() {
            diag::record(FaramirError::TxLogNotFound(label.clone()));
        } else {
            diag::record(FaramirError::HiveDirtyNoLogs(format!(
                "{label} ({} candidate(s) rejected)",
                selection.rejected.len()
            )));
        }
        out!("\t    [!] No transaction logs found, proceeding with dirty state");
        return Ok(OpenedHive {
            hive: hive.treat_hive_as_clean(),
            recovery: report,
        });
    }

    if !selection.has_matching() {
        diag::record(FaramirError::TxLogSequenceMismatch(format!(
            "{label}: every located log entry is older than the hive (secondary sequence {}); nothing to replay",
            header.secondary_sequence
        )));
        out!("\t    [!] Transaction logs are stale, proceeding with dirty state");
        return Ok(OpenedHive {
            hive: hive.treat_hive_as_clean(),
            recovery: report,
        });
    }

    for cand in selection.usable() {
        out!("\t    -> Applying {}", cand.path.display());
    }

    match apply_selection(hive, &selection) {
        Ok((clean, used)) => {
            report.logs_applied = true;
            diag::record(FaramirError::HiveRecovered(format!(
                "{label} using {}",
                used.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
            Ok(OpenedHive {
                hive: clean,
                recovery: report,
            })
        }
        Err(e) => {
            diag::record(e);
            diag::record(FaramirError::TxLogReplayFailed(format!(
                "{label}: continuing with the dirty on-disk state"
            )));
            let hive = parse_hive_file(&info.path, header).map_err(diag::record)?;
            Ok(OpenedHive {
                hive: hive.treat_hive_as_clean(),
                recovery: report,
            })
        }
    }
}

/// Convenience: classify + open a single file.
pub fn open_hive_path(path: &Path) -> Result<OpenedHive, FaramirError> {
    let info = classify_hive(path, path.parent().unwrap_or(path))?;
    open_hive(&info)
}

/// Re-export used by tests to build candidates manually.
pub fn candidate_paths(selection: &TxLogSelection) -> Vec<&TxLogCandidate> {
    selection.usable()
}
