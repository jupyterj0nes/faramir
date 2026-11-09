//! Diagnostics sink.
//!
//! Every degraded path (hive skipped, log rejected, technique panicked…)
//! records a [`FaramirError`] here. Errors and warnings are echoed to stderr
//! with their code; infos are only echoed in verbose mode. Tests drain the
//! sink to assert that the right code was produced.
//!
//! The sink is per thread. A worker thread of [`crate::jobs`] records into
//! its own while it analyses a target, drains it when the target is done and
//! hands the list back; the main thread puts the lists into its sink in
//! target order with [`absorb`], so the summary at the end is the same
//! whatever thread did the work. Quiet and verbose are process-wide.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::errors::{FaramirError, Severity};

thread_local! {
    static SINK: RefCell<Vec<FaramirError>> = const { RefCell::new(Vec::new()) };
}
static QUIET: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Suppress all stderr echo (the sink still collects everything).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Also echo `Info` level diagnostics to stderr.
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Record a diagnostic. Returns the same error so callers can write
/// `return Err(diag::record(err))`.
pub fn record(err: FaramirError) -> FaramirError {
    if !is_quiet() {
        match err.severity() {
            Severity::Error => eprintln!("\x1b[31m[ERROR] {err}\x1b[0m"),
            Severity::Warning => eprintln!("\x1b[33m[WARN]  {err}\x1b[0m"),
            Severity::Info => {
                if is_verbose() {
                    eprintln!("\x1b[36m[INFO]  {err}\x1b[0m");
                }
            }
        }
    }
    SINK.with(|s| s.borrow_mut().push(err.clone()));
    err
}

/// Put diagnostics a worker recorded (and already echoed) into this thread's
/// sink, in the order given.
pub fn absorb(errs: Vec<FaramirError>) {
    SINK.with(|s| s.borrow_mut().extend(errs));
}

/// Remove and return every recorded diagnostic.
pub fn drain() -> Vec<FaramirError> {
    SINK.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Copy of every recorded diagnostic.
pub fn snapshot() -> Vec<FaramirError> {
    SINK.with(|s| s.borrow().clone())
}

pub fn clear() {
    SINK.with(|s| s.borrow_mut().clear());
}

/// Number of recorded diagnostics with the given text code (e.g. `ERR_WIN_TX_LOG_NOT_FOUND`).
pub fn count(code: &str) -> usize {
    SINK.with(|s| s.borrow().iter().filter(|e| e.code() == code).count())
}

pub fn has(code: &str) -> bool {
    count(code) > 0
}

/// Aggregated counters per severity.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

impl Summary {
    pub fn total(&self) -> usize {
        self.errors + self.warnings + self.infos
    }
}

pub fn summary() -> Summary {
    SINK.with(|s| {
        let mut out = Summary::default();
        for e in s.borrow().iter() {
            match e.severity() {
                Severity::Error => out.errors += 1,
                Severity::Warning => out.warnings += 1,
                Severity::Info => out.infos += 1,
            }
        }
        out
    })
}

/// Extract a readable message out of a caught panic payload.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}
