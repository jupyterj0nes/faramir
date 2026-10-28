//! Tag findings that came out of carved hives and fold the ones the live
//! registry already shows.
//!
//! Every finding from a carved hive is marked `carved`. A carved copy of the
//! live SOFTWARE hive repeats every Run entry the analyst already has, so a
//! carved finding identical to a live one (same technique, value and access)
//! is dropped and counted; the ones that survive are what only exists in the
//! raw bytes. Among carved duplicates the copy with the latest hive write
//! time wins.

use std::collections::{HashMap, HashSet};

use super::hive::CarvedHive;
use crate::windows::deleted::SOURCE_DELETED;
use crate::windows::Persistence;

/// `source` prefix of a carved finding.
pub const SOURCE_CARVED: &str = "carved";
/// `source` prefix of a deleted key recovered inside a carved hive.
pub const SOURCE_CARVED_DELETED: &str = "carved+deleted";

/// `carved:<offset>:<kind>:<hive write time>` (or `carved+deleted:` for free cells).
pub fn source_tag(hive: Option<&CarvedHive>, was_deleted: bool) -> String {
    let prefix = if was_deleted { SOURCE_CARVED_DELETED } else { SOURCE_CARVED };
    match hive {
        Some(h) => format!("{prefix}:{:#x}:{}:{}", h.offset, h.kind, h.written()),
        None => format!("{prefix}:?"),
    }
}

pub fn is_carved_source(source: &str) -> bool {
    source == SOURCE_CARVED
        || source == SOURCE_CARVED_DELETED
        || source.starts_with("carved:")
        || source.starts_with("carved+deleted:")
}

/// Same technique, same key/location, same value, same access. The location
/// matters: two services sharing an `ImagePath` are two findings.
fn identity(p: &Persistence) -> (String, String, String, String) {
    (p.technique.clone(), p.path.to_lowercase(), p.value.to_lowercase(), p.access_gained.clone())
}

/// Result of [`tag_and_fold`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FoldReport {
    pub kept: usize,
    /// Dropped because the live registry has the same finding.
    pub folded_into_live: usize,
    /// Dropped because another carved hive had the same finding.
    pub folded_into_carved: usize,
}

/// Tag `findings` (produced by running the techniques on the carved hives)
/// and drop what `live` already shows.
pub fn tag_and_fold(live: &[Persistence], findings: Vec<Persistence>, hives: &[CarvedHive]) -> (Vec<Persistence>, FoldReport) {
    // only what the live registry shows right now; a snapshot-only or
    // deleted-cell finding is not "live", so a carved copy of it is kept
    let live_ids: HashSet<_> = live.iter().filter(|p| p.source.is_empty()).map(identity).collect();
    let by_path: HashMap<String, &CarvedHive> = hives.iter().map(|h| (h.path.to_string_lossy().to_string(), h)).collect();
    let mut report = FoldReport::default();
    let mut out: Vec<Persistence> = Vec::new();
    let mut best: HashMap<(String, String, String, String), (usize, u64)> = HashMap::new();

    for p in findings {
        let id = identity(&p);
        if live_ids.contains(&id) {
            report.folded_into_live += 1;
            continue;
        }
        let hive = by_path.get(&p.origin).copied();
        let written = hive.map(|h| h.header.timestamp_filetime).unwrap_or(0);
        let was_deleted = p.source == SOURCE_DELETED;
        let mut tagged = p.clone();
        tagged.source = source_tag(hive, was_deleted);
        tagged.path = match hive {
            Some(h) => format!("carved {}: {}", h.describe(), p.path),
            None => format!("carved: {}", p.path),
        };
        match best.get(&id) {
            Some(&(idx, prev_written)) => {
                report.folded_into_carved += 1;
                if written > prev_written {
                    out[idx] = tagged;
                    best.insert(id, (idx, written));
                }
            }
            None => {
                best.insert(id, (out.len(), written));
                out.push(tagged);
            }
        }
    }
    report.kept = out.len();
    (out, report)
}
