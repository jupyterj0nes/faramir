//! Faramir's view of the shared scanner (`blockcarve::scan`): the same engine,
//! with every read failure, stall and abort also recorded in the diagnostics
//! sink under faramir's error codes, so the end-of-run report lists them.

pub use blockcarve::scan::{
    HitAction, HitFn, ProgressFn, ScanConfig, ScanStats, BLOCK_SIZE, ERROR_SKIP, MAX_CONSECUTIVE_ERRORS, SECTOR, STALL_SKIP,
};
use blockcarve::source::{BlockError, BlockSource};

use crate::errors::FaramirError;
use crate::windows::diag;

/// A block source whose failures are recorded as they happen.
pub struct Diagnosing<'a> {
    inner: &'a mut dyn BlockSource,
}

impl<'a> Diagnosing<'a> {
    pub fn new(inner: &'a mut dyn BlockSource) -> Self {
        Diagnosing { inner }
    }
}

impl BlockSource for Diagnosing<'_> {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn stalls(&self) -> usize {
        self.inner.stalls()
    }

    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        let r = self.inner.read_block(offset, len);
        match &r {
            Err(BlockError::Io(e)) => {
                diag::record(FaramirError::CarveReadError(format!("{} at offset {offset:#x}: {e}", self.label())));
            }
            Err(BlockError::Stalled) => {
                diag::record(FaramirError::CarveReadStalled(format!(
                    "{} at offset {offset:#x}; skipping {} MB",
                    self.label(),
                    STALL_SKIP >> 20
                )));
            }
            _ => {}
        }
        r
    }
}

/// Visits every `signature` aligned to `cfg.step`; see `blockcarve::scan::scan_signatures`.
/// Read errors and stalls are recorded through [`Diagnosing`]; the larger skip after
/// repeated failures and an aborted scan are recorded from the scanner's notes.
pub fn scan_signatures(
    src: &mut dyn BlockSource,
    cfg: &ScanConfig,
    signature: &[u8],
    on_hit: &mut HitFn<'_>,
    progress: &mut ProgressFn<'_>,
) -> ScanStats {
    let label = src.label().to_string();
    let mut diagnosed = Diagnosing::new(src);
    let stats = blockcarve::scan::scan_signatures(&mut diagnosed, cfg, signature, on_hit, progress);
    for note in &stats.notes {
        if note.contains("consecutive failures") {
            diag::record(FaramirError::CarveReadError(note.clone()));
        }
    }
    if stats.aborted {
        let why = stats.notes.last().cloned().unwrap_or_else(|| format!("{label}: scan aborted"));
        diag::record(FaramirError::CarveAborted(why));
    }
    stats
}
