//! Run independent evidence targets on a few threads and hand the results
//! back in the order the targets were given.
//!
//! Every target (a disk image, a triage archive, a directory, a file) is
//! analysed by exactly the code that analysed it when faramir ran on one
//! thread; the only thing this module does is pick the next target for a
//! free worker and keep each result in the slot of its target. The caller
//! concatenates the slots in order, so the rows, the diagnostics and the CSV
//! are the same with one worker or with eight.
//!
//! A worker that panics on a target does not take the run down and does not
//! lose the other targets: the panic is caught, its message comes back as
//! [`Outcome::Panicked`] for that slot, and the next target is picked up. The
//! caller records it (6004) and ends with a non-zero exit code.
//!
//! The work closure runs on a worker thread even with one job, so the
//! thread-local state the parsers keep (evidence root, log index,
//! diagnostics sink) is the worker's own and the caller's is untouched.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::errors::FaramirError;
use crate::windows::diag;

/// Workers used when `--jobs` is not given: the cores available, at most this.
/// Each job needs about the memory of the largest dirty hive of its host,
/// which is what keeps the default small.
pub const DEFAULT_JOBS_CAP: usize = 4;

/// Workers to use when `--jobs` is not given, or is 0.
pub fn default_jobs() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, DEFAULT_JOBS_CAP)
}

/// What came out of one target.
#[derive(Debug)]
pub enum Outcome<R> {
    Done(R),
    /// The worker panicked on this target: the message of the panic and the
    /// diagnostics it had recorded on the target before panicking.
    Panicked(String, Vec<FaramirError>),
}

impl<R> Outcome<R> {
    pub fn is_done(&self) -> bool {
        matches!(self, Outcome::Done(_))
    }
}

/// Run `work` on every target with up to `jobs` worker threads (0 and 1 both
/// mean one worker). The result of `targets[i]` is `outcomes[i]`, whatever
/// thread ran it and whenever it finished.
pub fn run_all<T, R, F>(targets: &[T], jobs: usize, work: F) -> Vec<Outcome<R>>
where
    T: Sync,
    R: Send,
    F: Fn(usize, &T) -> R + Sync,
{
    if targets.is_empty() {
        return Vec::new();
    }
    let jobs = jobs.max(1).min(targets.len());
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Outcome<R>>>> = targets.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= targets.len() {
                    break;
                }
                let out = match catch_unwind(AssertUnwindSafe(|| work(i, &targets[i]))) {
                    Ok(r) => Outcome::Done(r),
                    Err(p) => Outcome::Panicked(diag::panic_message(&*p), diag::drain()),
                };
                *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(out);
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()).expect("every target was picked up by a worker"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn ids(outs: &[Outcome<usize>]) -> Vec<usize> {
        outs.iter().map(|o| match o { Outcome::Done(v) => *v, Outcome::Panicked(..) => usize::MAX }).collect()
    }

    #[test]
    fn results_come_back_in_target_order_whatever_finishes_first() {
        let targets: Vec<usize> = (0..24).collect();
        for jobs in [1, 2, 3, 8, 64] {
            let outs = run_all(&targets, jobs, |_, t| {
                // later targets finish first
                std::thread::sleep(Duration::from_millis((24 - *t as u64) % 7));
                *t * 10
            });
            assert_eq!(ids(&outs), targets.iter().map(|t| t * 10).collect::<Vec<_>>(), "jobs {jobs}");
        }
    }

    #[test]
    fn zero_jobs_means_one_and_more_jobs_than_targets_is_fine() {
        let targets = ["a", "b"];
        let outs = run_all(&targets, 0, |i, t| format!("{i}{t}"));
        assert!(matches!(&outs[..], [Outcome::Done(a), Outcome::Done(b)] if a == "0a" && b == "1b"));
        let outs = run_all(&targets, 100, |i, t| format!("{i}{t}"));
        assert!(matches!(&outs[..], [Outcome::Done(a), Outcome::Done(b)] if a == "0a" && b == "1b"));
        assert!(run_all(&[] as &[u8], 4, |_, _| 0).is_empty());
    }

    #[test]
    fn every_target_runs_exactly_once() {
        let targets: Vec<usize> = (0..50).collect();
        let runs = AtomicUsize::new(0);
        let outs = run_all(&targets, 6, |_, t| {
            runs.fetch_add(1, Ordering::SeqCst);
            *t
        });
        assert_eq!(runs.load(Ordering::SeqCst), 50);
        assert_eq!(ids(&outs), targets);
    }

    #[test]
    fn a_panicking_target_is_reported_in_its_slot_and_the_rest_complete() {
        let targets: Vec<usize> = (0..10).collect();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the test output clean
        let outs = run_all(&targets, 3, |_, t| {
            if *t == 4 {
                diag::set_quiet(true);
                diag::record(FaramirError::HiveOpenFailed("recorded before the panic".into()));
                panic!("target four is broken");
            }
            *t
        });
        std::panic::set_hook(prev);
        assert_eq!(outs.len(), 10);
        for (i, o) in outs.iter().enumerate() {
            match o {
                Outcome::Done(v) => assert_eq!(*v, i),
                Outcome::Panicked(msg, diagnostics) => {
                    assert_eq!(i, 4, "only target four panicked");
                    assert!(msg.contains("target four is broken"), "{msg}");
                    assert_eq!(diagnostics.len(), 1, "what the target recorded before the panic comes back with it");
                    assert_eq!(diagnostics[0].error_number(), 3001);
                }
            }
        }
        assert_eq!(outs.iter().filter(|o| !o.is_done()).count(), 1);
    }

    #[test]
    fn a_worker_keeps_its_own_thread_local_state() {
        thread_local! { static MARK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }
        MARK.with(|m| m.set(99));
        let outs = run_all(&[1u32, 2, 3], 1, |_, t| {
            // one worker: a worker's thread-local starts clean, not at the caller's 99
            let before = MARK.with(|m| m.get());
            MARK.with(|m| m.set(*t));
            before
        });
        assert!(outs.iter().all(|o| matches!(o, Outcome::Done(v) if *v != 99)));
        assert_eq!(MARK.with(|m| m.get()), 99, "the caller's state is untouched");
    }

    #[test]
    fn default_jobs_is_between_one_and_the_cap() {
        let d = default_jobs();
        assert!((1..=DEFAULT_JOBS_CAP).contains(&d), "{d}");
    }
}
