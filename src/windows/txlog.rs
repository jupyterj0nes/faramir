//! Transaction log (`.LOG1` / `.LOG2`) location and validation.
//!
//! Collectors lay evidence out in many ways: KAPE keeps logs next to the
//! hive, disk-image extraction renames user hives to `<user>_NTUSER.DAT`,
//! flattened collectors produce `C_Windows_System32_config_SYSTEM.LOG1`, and
//! some put logs in a parallel tree. The locator therefore:
//!
//! 1. looks in the hive's own folder (case-insensitive),
//! 2. otherwise indexes every `.LOG1`/`.LOG2`/`.LOG` under the evidence root
//!    and scores candidates by name and path similarity,
//! 3. verifies every candidate by parsing its base block: the embedded hive
//!    name must match the hive's, which disambiguates `NTUSER.DAT.LOG1` of
//!    different users,
//! 4. pre-validates each HvLE entry so a truncated or garbage log can never
//!    make the parser panic or allocate absurd buffers; a damaged tail is cut
//!    off and only the valid prefix is replayed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nt_hive2::transactionlog::TransactionLog;
use walkdir::WalkDir;

use super::diag;
use super::hives::{HiveHeader, HiveInfo, HiveKind};
use crate::errors::FaramirError;

pub const SECTOR_SIZE: usize = 512;
pub const HVLE_HEADER_SIZE: u64 = 40;
pub const HVLE_MAGIC: &[u8; 4] = b"HvLE";
pub const HBIN_ALIGNMENT: u32 = 4096;

/// Which slot a candidate belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxLogSlot {
    Log1,
    Log2,
    /// Legacy single `.LOG` (cannot be replayed, reported only).
    Legacy,
}

impl TxLogSlot {
    pub fn extension(&self) -> &'static str {
        match self {
            TxLogSlot::Log1 => ".LOG1",
            TxLogSlot::Log2 => ".LOG2",
            TxLogSlot::Legacy => ".LOG",
        }
    }
}

/// Summary of one HvLE entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLogEntrySummary {
    pub offset: u64,
    pub size: u32,
    pub sequence: u32,
    pub hbin_data_size: u32,
    pub dirty_pages: u32,
    pub payload_bytes: u64,
}

/// Result of inspecting a transaction log without the heavy parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLogSummary {
    pub path: PathBuf,
    pub file_len: u64,
    pub header: HiveHeader,
    pub entries: Vec<TxLogEntrySummary>,
    /// Bytes that are safe to hand to the parser (`file_len` when fully valid).
    pub usable_len: u64,
    /// Non-fatal problems detected while scanning.
    pub problems: Vec<FaramirError>,
}

impl TxLogSummary {
    pub fn first_sequence(&self) -> Option<u32> {
        self.entries.first().map(|e| e.sequence)
    }

    pub fn last_sequence(&self) -> Option<u32> {
        self.entries.last().map(|e| e.sequence)
    }

    pub fn needs_sanitizing(&self) -> bool {
        self.usable_len < self.file_len
    }

    pub fn embedded_name(&self) -> &str {
        &self.header.embedded_name
    }
}

/// How a (valid) log relates to the hive it was found for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxLogRelation {
    /// Continues the hive's secondary sequence number: will be applied.
    Matching,
    /// All entries are older than the hive: nothing to apply (normal for the other log).
    Stale,
    /// First entry is ahead of the hive: cannot be applied (missing intermediate log).
    Gap,
    /// Embedded hive name differs: belongs to another hive.
    Foreign,
}

/// Scan a transaction log held in memory.
pub fn inspect_transaction_log_bytes(path: &Path, bytes: &[u8]) -> Result<TxLogSummary, FaramirError> {
    let label = path.display().to_string();
    let file_len = bytes.len() as u64;
    if bytes.len() < SECTOR_SIZE {
        return Err(FaramirError::TxLogTruncated(format!(
            "{label} ({} bytes, need at least {SECTOR_SIZE})",
            bytes.len()
        )));
    }
    let header = match HiveHeader::parse(&bytes[..SECTOR_SIZE], &label) {
        Ok(h) => h,
        Err(FaramirError::HiveSignatureInvalid(d)) => return Err(FaramirError::TxLogSignatureInvalid(d)),
        Err(e) => return Err(e),
    };
    if header.is_legacy_log() {
        return Err(FaramirError::TxLogLegacyFormat(format!(
            "{label} (file type {})",
            header.file_type
        )));
    }
    if header.is_primary() {
        return Err(FaramirError::TxLogSignatureInvalid(format!(
            "{label} (file type 0: this is a primary hive, not a log)"
        )));
    }
    if !header.is_new_log() {
        return Err(FaramirError::TxLogSignatureInvalid(format!(
            "{label} (unknown file type {})",
            header.file_type
        )));
    }

    let mut problems = Vec::new();
    if !header.checksum_valid() {
        problems.push(FaramirError::HiveChecksumInvalid(format!(
            "{label} (log base block, stored 0x{:08x}, calculated 0x{:08x})",
            header.checksum_stored, header.checksum_calculated
        )));
    }

    let mut entries = Vec::new();
    let mut pos: u64 = SECTOR_SIZE as u64;
    let mut usable_len = file_len;

    loop {
        if pos + HVLE_HEADER_SIZE > file_len {
            break;
        }
        let p = pos as usize;
        if &bytes[p..p + 4] != HVLE_MAGIC {
            break;
        }
        let size = u32::from_le_bytes([bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]]);
        let flags = u32::from_le_bytes([bytes[p + 8], bytes[p + 9], bytes[p + 10], bytes[p + 11]]);
        let sequence = u32::from_le_bytes([bytes[p + 12], bytes[p + 13], bytes[p + 14], bytes[p + 15]]);
        let hbin_data_size =
            u32::from_le_bytes([bytes[p + 16], bytes[p + 17], bytes[p + 18], bytes[p + 19]]);
        let dirty_pages =
            u32::from_le_bytes([bytes[p + 20], bytes[p + 21], bytes[p + 22], bytes[p + 23]]);

        let invalid = |why: String| FaramirError::TxLogEntryInvalid(format!(
            "{label} entry #{} at offset {pos}: {why}",
            entries.len() + 1
        ));

        if (size as u64) < HVLE_HEADER_SIZE {
            problems.push(invalid(format!("size {size} smaller than header")));
            usable_len = pos;
            break;
        }
        if !(size as u64).is_multiple_of(SECTOR_SIZE as u64) {
            problems.push(invalid(format!("size {size} not a multiple of {SECTOR_SIZE}")));
            usable_len = pos;
            break;
        }
        if pos + size as u64 > file_len {
            problems.push(FaramirError::TxLogTruncated(format!(
                "{label} entry #{} at offset {pos} claims {size} bytes but only {} remain",
                entries.len() + 1,
                file_len - pos
            )));
            usable_len = pos;
            break;
        }
        if flags & !1 != 0 {
            problems.push(invalid(format!("unexpected flags 0x{flags:08x}")));
            usable_len = pos;
            break;
        }
        if dirty_pages == 0 {
            problems.push(invalid("zero dirty pages".to_string()));
            usable_len = pos;
            break;
        }
        if hbin_data_size == 0 || !hbin_data_size.is_multiple_of(HBIN_ALIGNMENT) {
            problems.push(invalid(format!("hbin data size {hbin_data_size} not 4096-aligned")));
            usable_len = pos;
            break;
        }
        let refs_bytes = (dirty_pages as u64).saturating_mul(8);
        if HVLE_HEADER_SIZE + refs_bytes > size as u64 {
            problems.push(invalid(format!("{dirty_pages} page references do not fit in {size} bytes")));
            usable_len = pos;
            break;
        }
        let mut payload: u64 = 0;
        let mut bad_ref: Option<String> = None;
        for i in 0..dirty_pages as usize {
            let r = p + HVLE_HEADER_SIZE as usize + i * 8;
            let off = u32::from_le_bytes([bytes[r], bytes[r + 1], bytes[r + 2], bytes[r + 3]]);
            let sz = u32::from_le_bytes([bytes[r + 4], bytes[r + 5], bytes[r + 6], bytes[r + 7]]);
            if sz == 0 {
                bad_ref = Some(format!("page reference #{i} has zero size"));
                break;
            }
            match off.checked_add(sz) {
                Some(end) if end <= hbin_data_size => {}
                _ => {
                    bad_ref = Some(format!(
                        "page reference #{i} (offset {off}, size {sz}) exceeds hbin data size {hbin_data_size}"
                    ));
                    break;
                }
            }
            payload = payload.saturating_add(sz as u64);
        }
        if let Some(why) = bad_ref {
            problems.push(invalid(why));
            usable_len = pos;
            break;
        }
        if HVLE_HEADER_SIZE + refs_bytes + payload > size as u64 {
            problems.push(invalid(format!(
                "dirty page payload {payload} bytes does not fit in entry of {size} bytes"
            )));
            usable_len = pos;
            break;
        }

        entries.push(TxLogEntrySummary {
            offset: pos,
            size,
            sequence,
            hbin_data_size,
            dirty_pages,
            payload_bytes: payload,
        });
        pos += size as u64;
    }

    if entries.is_empty() {
        return Err(FaramirError::TxLogNoEntries(label));
    }

    for w in entries.windows(2) {
        if w[1].sequence != w[0].sequence.wrapping_add(1) {
            problems.push(FaramirError::TxLogSequenceMismatch(format!(
                "{label}: entry sequence jumps from {} to {}",
                w[0].sequence, w[1].sequence
            )));
            break;
        }
    }

    Ok(TxLogSummary {
        path: path.to_path_buf(),
        file_len,
        header,
        entries,
        usable_len,
        problems,
    })
}

/// Read and scan a transaction log from disk.
pub fn inspect_transaction_log(path: &Path) -> Result<TxLogSummary, FaramirError> {
    let bytes = std::fs::read(path)
        .map_err(|e| FaramirError::TxLogOpenFailed(format!("{}: {e}", path.display())))?;
    inspect_transaction_log_bytes(path, &bytes)
}

/// Compare a scanned log with the hive it is meant for.
pub fn relation_to_hive(summary: &TxLogSummary, hive: &HiveHeader) -> TxLogRelation {
    let log_name = summary.header.embedded_name.trim();
    let hive_name = hive.embedded_name.trim();
    if !log_name.is_empty() && !hive_name.is_empty() && !log_name.eq_ignore_ascii_case(hive_name) {
        return TxLogRelation::Foreign;
    }
    let last = summary.last_sequence().unwrap_or(0);
    let first = summary.first_sequence().unwrap_or(0);
    if last <= hive.secondary_sequence {
        return TxLogRelation::Stale;
    }
    if first > hive.secondary_sequence.wrapping_add(1) {
        return TxLogRelation::Gap;
    }
    TxLogRelation::Matching
}

/// One file considered as a log for a hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLogCandidate {
    pub path: PathBuf,
    pub slot: TxLogSlot,
    pub same_directory: bool,
    pub score: i64,
    pub summary: Option<TxLogSummary>,
    pub relation: Option<TxLogRelation>,
}

/// Final choice for a hive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxLogSelection {
    pub log1: Option<TxLogCandidate>,
    pub log2: Option<TxLogCandidate>,
    pub rejected: Vec<(PathBuf, FaramirError)>,
}

impl TxLogSelection {
    pub fn is_empty(&self) -> bool {
        self.log1.is_none() && self.log2.is_none()
    }

    /// Candidates worth handing to the parser (Matching or Stale; Stale is
    /// harmless because the parser drops old entries itself).
    pub fn usable(&self) -> Vec<&TxLogCandidate> {
        [&self.log1, &self.log2]
            .into_iter()
            .flatten()
            .filter(|c| matches!(c.relation, Some(TxLogRelation::Matching) | Some(TxLogRelation::Stale)))
            .collect()
    }

    /// At least one log continues the hive's sequence (something will change).
    pub fn has_matching(&self) -> bool {
        [&self.log1, &self.log2]
            .into_iter()
            .flatten()
            .any(|c| c.relation == Some(TxLogRelation::Matching))
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        [&self.log1, &self.log2]
            .into_iter()
            .flatten()
            .map(|c| c.path.clone())
            .collect()
    }
}

/// (upper-case file name, path) of every log file under an evidence root.
pub type LogIndex = Rc<Vec<(String, PathBuf)>>;

thread_local! {
    static LOG_INDEX: RefCell<HashMap<PathBuf, LogIndex>> = RefCell::new(HashMap::new());
}

/// Index of every `.LOG1`/`.LOG2`/`.LOG` under `root`, cached per root.
pub fn log_index(root: &Path) -> LogIndex {
    let key = root.to_path_buf();
    if let Some(cached) = LOG_INDEX.with(|m| m.borrow().get(&key).cloned()) {
        return cached;
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if name.ends_with(".LOG1") || name.ends_with(".LOG2") || name.ends_with(".LOG") {
            files.push((name, entry.path().to_path_buf()));
        }
    }
    let rc = Rc::new(files);
    LOG_INDEX.with(|m| m.borrow_mut().insert(key, rc.clone()));
    rc
}

/// Forget cached indexes (tests reuse temp dirs; the CLI never needs this).
pub fn clear_log_index() {
    LOG_INDEX.with(|m| m.borrow_mut().clear());
}

/// Does `candidate_name` (upper case) look like the log of `hive_name` in `slot`?
pub fn name_matches(hive_name: &str, hive_kind: HiveKind, candidate_name: &str, slot: TxLogSlot) -> bool {
    let hive_upper = hive_name.to_uppercase();
    let cand = candidate_name.to_uppercase();
    let ext = slot.extension();
    if !cand.ends_with(ext) {
        return false;
    }
    let stem = &cand[..cand.len() - ext.len()];
    if stem == hive_upper {
        return true;
    }
    if let Some(canon) = hive_kind.canonical_file_name() {
        if stem == canon
            || stem.ends_with(&format!("_{canon}"))
            || stem.ends_with(&format!("-{canon}"))
            || stem.ends_with(&format!(".{canon}"))
        {
            return true;
        }
        // Hive stored with a copy suffix (SOFTWARE.hve) but log without it.
        if HiveKind::from_file_name(stem) == hive_kind && hive_kind != HiveKind::Unknown {
            return true;
        }
    }
    false
}

fn trailing_components(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_uppercase()),
            _ => None,
        })
        .collect()
}

/// Pure path-based score: higher is closer to the hive.
pub fn score_candidate(hive_path: &Path, candidate: &Path) -> i64 {
    let mut score: i64 = 0;
    let hive_parent = hive_path.parent().unwrap_or(hive_path);
    let cand_parent = candidate.parent().unwrap_or(candidate);
    if hive_parent == cand_parent {
        score += 1000;
    }
    let hp = trailing_components(hive_parent);
    let cp = trailing_components(cand_parent);
    let mut matched = 0;
    for (a, b) in hp.iter().rev().zip(cp.iter().rev()) {
        if a == b {
            matched += 1;
        } else {
            break;
        }
    }
    if matched >= 1 {
        score += 300;
    }
    if matched > 1 {
        score += 100 * (matched as i64 - 1).min(3);
    }
    let hive_name = hive_path.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
    let cand_name = candidate.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
    if cand_name.starts_with(&format!("{hive_name}.")) {
        score += 50;
    }
    score
}

/// All files that could be the `slot` log of this hive, nearest first.
pub fn find_log_candidates(hive: &HiveInfo, slot: TxLogSlot) -> Vec<PathBuf> {
    let hive_name = hive.file_name();
    let mut out: Vec<PathBuf> = Vec::new();

    if let Some(parent) = hive.path.parent() {
        if let Ok(rd) = std::fs::read_dir(parent) {
            for e in rd.flatten() {
                if !e.path().is_file() {
                    continue;
                }
                let n = e.file_name().to_string_lossy().to_string();
                if name_matches(&hive_name, hive.kind, &n, slot) {
                    out.push(e.path());
                }
            }
        }
    }

    if hive.evidence_root.is_dir() {
        for (upper, path) in log_index(&hive.evidence_root).iter() {
            if out.contains(path) {
                continue;
            }
            if name_matches(&hive_name, hive.kind, upper, slot) {
                out.push(path.clone());
            }
        }
    }

    out.sort_by(|a, b| {
        score_candidate(&hive.path, b)
            .cmp(&score_candidate(&hive.path, a))
            .then_with(|| a.cmp(b))
    });
    out
}

fn evaluate(hive: &HiveInfo, path: &Path, slot: TxLogSlot) -> Result<TxLogCandidate, FaramirError> {
    let summary = inspect_transaction_log(path)?;
    let relation = relation_to_hive(&summary, &hive.header);
    if relation == TxLogRelation::Foreign {
        return Err(FaramirError::TxLogHiveMismatch(format!(
            "{} says '{}' but hive {} says '{}'",
            path.display(),
            summary.header.embedded_name,
            hive.path.display(),
            hive.header.embedded_name
        )));
    }
    let same_directory = hive.path.parent() == path.parent();
    let mut score = score_candidate(&hive.path, path);
    score += match relation {
        TxLogRelation::Matching => 500,
        TxLogRelation::Stale | TxLogRelation::Gap => 100,
        TxLogRelation::Foreign => -10_000,
    };
    if !summary.header.embedded_name.trim().is_empty()
        && summary
            .header
            .embedded_name
            .trim()
            .eq_ignore_ascii_case(hive.header.embedded_name.trim())
    {
        score += 200;
    }
    Ok(TxLogCandidate {
        path: path.to_path_buf(),
        slot,
        same_directory,
        score,
        summary: Some(summary),
        relation: Some(relation),
    })
}

fn pick(hive: &HiveInfo, slot: TxLogSlot, rejected: &mut Vec<(PathBuf, FaramirError)>) -> Option<TxLogCandidate> {
    let mut evaluated: Vec<TxLogCandidate> = Vec::new();
    for path in find_log_candidates(hive, slot) {
        match evaluate(hive, &path, slot) {
            Ok(c) => evaluated.push(c),
            Err(e) => rejected.push((path, e)),
        }
    }
    if evaluated.is_empty() {
        return None;
    }
    evaluated.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
    if evaluated.len() > 1 && evaluated[0].score == evaluated[1].score {
        diag::record(FaramirError::TxLogAmbiguous(format!(
            "{} for {}: picked {} over {}",
            slot.extension(),
            hive.path.display(),
            evaluated[0].path.display(),
            evaluated[1].path.display()
        )));
    }
    let chosen = evaluated.swap_remove(0);
    if !chosen.same_directory {
        diag::record(FaramirError::TxLogRemoteMatch(format!(
            "{} -> {}",
            hive.path.display(),
            chosen.path.display()
        )));
    }
    if let Some(summary) = &chosen.summary {
        for p in &summary.problems {
            diag::record(p.clone());
        }
    }
    Some(chosen)
}

/// LOG1 and LOG2 alternate, so a log whose first entry is "ahead" of the hive
/// is fine when the other log supplies the intermediate sequence numbers.
/// Re-evaluates both candidates against the union of their entries.
pub fn reconcile_pair(log1: &mut Option<TxLogCandidate>, log2: &mut Option<TxLogCandidate>, hive: &HiveHeader) {
    let mut seqs: Vec<u32> = Vec::new();
    for c in [log1.as_ref(), log2.as_ref()].into_iter().flatten() {
        if let Some(s) = &c.summary {
            seqs.extend(s.entries.iter().map(|e| e.sequence));
        }
    }
    seqs.sort_unstable();
    seqs.dedup();
    let mut reachable: Vec<u32> = Vec::new();
    let mut next = hive.secondary_sequence.wrapping_add(1);
    while seqs.binary_search(&next).is_ok() {
        reachable.push(next);
        next = next.wrapping_add(1);
    }
    for c in [log1.as_mut(), log2.as_mut()].into_iter().flatten() {
        if c.relation == Some(TxLogRelation::Foreign) {
            continue;
        }
        let Some(s) = &c.summary else { continue };
        let mine: Vec<u32> = s.entries.iter().map(|e| e.sequence).collect();
        let relation = if mine.iter().any(|q| reachable.contains(q)) {
            TxLogRelation::Matching
        } else if mine.iter().all(|q| *q <= hive.secondary_sequence) {
            TxLogRelation::Stale
        } else {
            TxLogRelation::Gap
        };
        c.relation = Some(relation);
    }
}

/// Locate, verify and rank the logs of a dirty hive.
pub fn locate_transaction_logs(hive: &HiveInfo) -> TxLogSelection {
    let mut rejected = Vec::new();
    let mut log1 = pick(hive, TxLogSlot::Log1, &mut rejected);
    let mut log2 = pick(hive, TxLogSlot::Log2, &mut rejected);
    reconcile_pair(&mut log1, &mut log2, &hive.header);
    for c in [log1.as_ref(), log2.as_ref()].into_iter().flatten() {
        if c.relation == Some(TxLogRelation::Gap) {
            diag::record(FaramirError::TxLogSequenceMismatch(format!(
                "{}: first entry {} is ahead of hive secondary sequence {} (intermediate log missing)",
                c.path.display(),
                c.summary.as_ref().and_then(|s| s.first_sequence()).unwrap_or(0),
                hive.header.secondary_sequence
            )));
        }
    }

    if log1.is_none() && log2.is_none() {
        for legacy in find_log_candidates(hive, TxLogSlot::Legacy) {
            rejected.push((
                legacy.clone(),
                FaramirError::TxLogLegacyFormat(legacy.display().to_string()),
            ));
        }
    }
    for (path, err) in &rejected {
        let _ = path;
        diag::record(err.clone());
    }
    TxLogSelection { log1, log2, rejected }
}

/// Parse a candidate with nt_hive2, after cutting off any damaged tail.
pub fn load_transaction_log(cand: &TxLogCandidate) -> Result<TransactionLog, FaramirError> {
    let label = cand.path.display().to_string();
    let summary = cand
        .summary
        .as_ref()
        .ok_or_else(|| FaramirError::TxLogOpenFailed(format!("{label}: not inspected")))?;

    let temp_copy: Option<PathBuf> = if summary.needs_sanitizing() {
        let bytes = std::fs::read(&cand.path)
            .map_err(|e| FaramirError::TxLogOpenFailed(format!("{label}: {e}")))?;
        let cut = (summary.usable_len as usize).min(bytes.len());
        let tmp = std::env::temp_dir().join(format!(
            "faramir_txlog_{}_{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut f = File::create(&tmp)
            .map_err(|e| FaramirError::TxLogOpenFailed(format!("{label}: cannot stage sanitized copy: {e}")))?;
        f.write_all(&bytes[..cut])
            .map_err(|e| FaramirError::TxLogOpenFailed(format!("{label}: cannot stage sanitized copy: {e}")))?;
        diag::record(FaramirError::TxLogPartiallyApplied(format!(
            "{label}: using first {cut} of {} bytes ({} valid entries)",
            bytes.len(),
            summary.entries.len()
        )));
        Some(tmp)
    } else {
        None
    };

    let source = temp_copy.clone().unwrap_or_else(|| cand.path.clone());
    let file = File::open(&source).map_err(|e| FaramirError::TxLogOpenFailed(format!("{label}: {e}")))?;
    let parsed = catch_unwind(AssertUnwindSafe(|| TransactionLog::try_from(file)));
    if let Some(tmp) = temp_copy {
        let _ = std::fs::remove_file(tmp);
    }
    match parsed {
        Ok(Ok(log)) => Ok(log),
        Ok(Err(e)) => Err(FaramirError::TxLogApplyFailed(format!("{label}: {e}"))),
        Err(p) => Err(FaramirError::TxLogApplyPanic(format!(
            "{label}: {}",
            diag::panic_message(&*p)
        ))),
    }
}
