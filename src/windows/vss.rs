//! Volume Shadow Copy awareness for findings.
//!
//! Image ingestion stages every snapshot under `partition_<n>_vss_<m>/` with a
//! `VSS_INFO.txt` sidecar. Techniques run over live and snapshot hives alike;
//! this module then folds the result: a finding that exists live is reported
//! once, a finding that only exists in a snapshot is reported as persistence
//! that was removed after that snapshot was taken.

use std::collections::HashSet;
use std::path::{Component, Path};

use super::techniques::Persistence;

/// Which snapshot a staged artifact came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssSnapshot {
    pub partition: usize,
    pub store: usize,
    /// `YYYY-MM-DD HH:MM:SS UTC` or `unknown`.
    pub created: String,
    pub sequence: u64,
}

impl VssSnapshot {
    pub fn tag(&self) -> String {
        format!("vss:{}:{}", self.store, self.created)
    }
}

/// Parse `partition_<n>_vss_<m>` from a path component.
pub fn parse_vss_dir_name(name: &str) -> Option<(usize, usize)> {
    let rest = name.strip_prefix("partition_")?;
    let (part, store) = rest.split_once("_vss_")?;
    Some((part.parse().ok()?, store.parse().ok()?))
}

/// Parse the `VSS_INFO.txt` sidecar (`key=value` lines).
pub fn parse_vss_info(text: &str, partition: usize, store: usize) -> VssSnapshot {
    let mut snap = VssSnapshot { partition, store, created: "unknown".to_string(), sequence: 0 };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "created" => snap.created = v.trim().to_string(),
            "sequence" => snap.sequence = v.trim().parse().unwrap_or(0),
            "store" => snap.store = v.trim().parse().unwrap_or(store),
            "partition" => snap.partition = v.trim().parse().unwrap_or(partition),
            _ => {}
        }
    }
    snap
}

/// The snapshot an artifact path belongs to, if any (reads the sidecar when present).
pub fn snapshot_of(path: &Path) -> Option<VssSnapshot> {
    let mut prefix = std::path::PathBuf::new();
    let mut found: Option<(usize, usize, std::path::PathBuf)> = None;
    for c in path.components() {
        prefix.push(c.as_os_str());
        if let Component::Normal(n) = c {
            if let Some((p, s)) = parse_vss_dir_name(&n.to_string_lossy()) {
                found = Some((p, s, prefix.clone()));
            }
        }
    }
    let (partition, store, dir) = found?;
    let text = std::fs::read_to_string(dir.join(super::super::ingest::image::VSS_INFO_FILE)).unwrap_or_default();
    Some(parse_vss_info(&text, partition, store))
}

fn is_vss_path(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|c| matches!(c, Component::Normal(n) if parse_vss_dir_name(&n.to_string_lossy()).is_some()))
}

fn identity(p: &Persistence) -> (String, String, String) {
    (p.technique.clone(), p.value.to_lowercase(), p.access_gained.clone())
}

/// File a finding was read from: the stamped origin, or the path field for
/// findings produced before stamping existed.
fn origin_of(p: &Persistence) -> &str {
    if p.origin.is_empty() { &p.path } else { &p.origin }
}

/// Keep live findings; keep a snapshot finding only when nothing equivalent
/// exists live (same technique, value and access), tagging it with its
/// snapshot. Equivalent snapshot findings across several stores collapse to
/// the most recent snapshot.
pub fn fold_vss_findings(findings: Vec<Persistence>) -> Vec<Persistence> {
    let live: HashSet<(String, String, String)> = findings
        .iter()
        .filter(|p| !is_vss_path(origin_of(p)))
        .map(identity)
        .collect();
    let mut out: Vec<Persistence> = Vec::new();
    let mut seen_removed: std::collections::HashMap<(String, String, String), usize> = std::collections::HashMap::new();

    for p in findings {
        if !is_vss_path(origin_of(&p)) {
            out.push(p);
            continue;
        }
        let id = identity(&p);
        if live.contains(&id) {
            continue;
        }
        let snap = snapshot_of(Path::new(origin_of(&p)));
        let (tag, created) = match &snap {
            Some(s) => (s.tag(), s.created.clone()),
            None => ("vss:?:unknown".to_string(), "unknown".to_string()),
        };
        let mut tagged = p.clone();
        tagged.source = tag;
        tagged.path = format!("VSS snapshot created {created}, gone from live volume: {}", p.path);
        match seen_removed.get(&id) {
            Some(&idx) => {
                // prefer the most recent snapshot (highest sequence) as the last sighting
                let prev_seq = out[idx].source.split(':').nth(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                let this_seq = snap.as_ref().map(|s| s.store as u64).unwrap_or(0);
                if this_seq > prev_seq {
                    out[idx] = tagged;
                }
            }
            None => {
                seen_removed.insert(id, out.len());
                out.push(tagged);
            }
        }
    }
    out
}
