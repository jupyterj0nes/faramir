//! Signature scanner over a [`BlockSource`].
//!
//! Reads the source in large blocks, keeps a carry-over so a structure that
//! starts near the end of one block is seen whole in the next, and visits
//! every aligned signature exactly once. The hit callback may read anywhere
//! in the source (to pull a whole hive out) and may ask the scanner to jump
//! past what it consumed.

use super::source::{BlockError, BlockSource};
use crate::errors::FaramirError;
use crate::windows::diag;

/// Bytes read per iteration.
pub const BLOCK_SIZE: usize = 4 << 20;
/// Signatures are only looked for at multiples of this (hives are cluster/page aligned).
pub const SECTOR: usize = 512;
/// Window skipped after a stalled read.
pub const STALL_SKIP: u64 = 32 << 20;
/// Window skipped after too many consecutive read failures.
pub const ERROR_SKIP: u64 = 64 << 20;
/// Consecutive failed blocks tolerated before the larger skip kicks in.
pub const MAX_CONSECUTIVE_ERRORS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfig {
    pub block_size: usize,
    /// Bytes after a signature the callback needs to see in one piece.
    pub window: usize,
    /// Alignment of candidate signatures.
    pub step: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig { block_size: BLOCK_SIZE, window: 4096 + 32, step: SECTOR }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanStats {
    pub bytes_read: u64,
    pub blocks: usize,
    /// Signatures handed to the callback.
    pub signatures: usize,
    pub read_errors: usize,
    pub stalls: usize,
    /// Bytes jumped over (after errors, stalls or at the callback's request).
    pub bytes_skipped: u64,
    pub aborted: bool,
}

/// What the hit callback wants the scanner to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitAction {
    Continue,
    /// Resume scanning at this absolute offset (ignored when not past the hit).
    SkipTo(u64),
}

/// Callback: `(source, absolute offset of the signature, bytes from the signature onwards)`.
pub type HitFn<'a> = dyn FnMut(&mut dyn BlockSource, u64, &[u8]) -> HitAction + 'a;
/// Progress callback: `(offset reached, total size)`.
pub type ProgressFn<'a> = dyn FnMut(u64, u64) + 'a;

/// Visit every `signature` aligned to `cfg.step`. Read failures are recorded
/// in the diagnostics sink and skipped; the scan never aborts on bad sectors.
pub fn scan_signatures(
    src: &mut dyn BlockSource,
    cfg: &ScanConfig,
    signature: &[u8],
    on_hit: &mut HitFn<'_>,
    progress: &mut ProgressFn<'_>,
) -> ScanStats {
    let mut stats = ScanStats::default();
    let size = src.size();
    let label = src.label().to_string();
    if size == 0 {
        stats.aborted = true;
        diag::record(FaramirError::CarveAborted(format!("{label}: source is empty")));
        return stats;
    }
    let step = cfg.step.max(1) as u64;
    let window = cfg.window.max(signature.len());

    let mut offset: u64 = 0;
    // bytes [offset - carry.len(), offset) kept from the previous block
    let mut carry: Vec<u8> = Vec::new();
    // every hit whose window ends at or before this offset has been handled
    let mut processed_until: u64 = 0;
    let mut consecutive_errors = 0usize;

    while offset < size {
        progress(offset, size);
        let want = cfg.block_size.min((size - offset) as usize);
        let block = match src.read_block(offset, want) {
            Ok(b) if b.is_empty() => break,
            Ok(b) => {
                consecutive_errors = 0;
                b
            }
            Err(BlockError::Stalled) => {
                stats.stalls += 1;
                let skip = STALL_SKIP.min(size - offset);
                diag::record(FaramirError::CarveReadStalled(format!(
                    "{label} at offset {offset:#x}; skipping {} MB",
                    skip >> 20
                )));
                offset += skip;
                stats.bytes_skipped += skip;
                carry.clear();
                processed_until = offset;
                continue;
            }
            Err(BlockError::Unavailable(e)) => {
                stats.aborted = true;
                diag::record(FaramirError::CarveAborted(format!("{label} at offset {offset:#x}: {e}")));
                break;
            }
            Err(BlockError::Io(e)) => {
                stats.read_errors += 1;
                consecutive_errors += 1;
                let skip = if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                    diag::record(FaramirError::CarveReadError(format!(
                        "{label} at offset {offset:#x}: {e} ({consecutive_errors} consecutive failures, skipping {} MB)",
                        ERROR_SKIP >> 20
                    )));
                    consecutive_errors = 0;
                    ERROR_SKIP
                } else {
                    diag::record(FaramirError::CarveReadError(format!("{label} at offset {offset:#x}: {e}")));
                    want as u64
                };
                let skip = skip.min(size - offset);
                offset += skip;
                stats.bytes_skipped += skip;
                carry.clear();
                processed_until = offset;
                continue;
            }
        };
        stats.blocks += 1;
        stats.bytes_read += block.len() as u64;

        let base = offset - carry.len() as u64;
        let mut buf = std::mem::take(&mut carry);
        buf.extend_from_slice(&block);
        let end_abs = base + buf.len() as u64;
        let at_eof = end_abs >= size || block.len() < want;

        // first position in `buf` whose absolute offset is step-aligned
        let mut pos = (base.div_ceil(step) * step - base) as usize;
        let mut skip_to: Option<u64> = None;
        while pos + signature.len() <= buf.len() {
            let abs = base + pos as u64;
            let whole_window = pos + window <= buf.len() || at_eof;
            if abs + window as u64 > processed_until && whole_window && &buf[pos..pos + signature.len()] == signature {
                stats.signatures += 1;
                match on_hit(src, abs, &buf[pos..]) {
                    HitAction::Continue => {}
                    HitAction::SkipTo(t) if t > abs => {
                        skip_to = Some(t);
                        break;
                    }
                    HitAction::SkipTo(_) => {}
                }
            }
            pos += step as usize;
        }

        if let Some(t) = skip_to {
            let t = t.min(size);
            if t > end_abs {
                stats.bytes_skipped += t - end_abs;
            }
            offset = t;
            carry.clear();
            processed_until = t;
            continue;
        }

        if at_eof {
            offset = end_abs;
            break;
        }
        let keep = window.min(buf.len());
        carry = buf[buf.len() - keep..].to_vec();
        processed_until = end_abs;
        offset = end_abs;
    }
    progress(offset.min(size), size);
    stats
}
