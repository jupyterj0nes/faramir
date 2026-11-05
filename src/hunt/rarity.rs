//! The statistical side: how unusual is each row compared with the rows of
//! the same technique in this run? Kansa-style stacking (how many rows share
//! its folder and name shape, whether it was written in a burst with other
//! techniques, on how many hosts the entry appears), summed into one
//! statistic and calibrated against the run's own rows the way masstin's
//! graph-hunt does. The only chosen number is alpha.
//!
//! A conformal p-value against N reference rows can never go below
//! 1/(N+1), so the rows put to the test must be few compared with the
//! reference, exactly as masstin tests the window days against the baseline
//! days. Three modes, per operating system:
//!
//! * **baseline** (`--baseline`): reference = rows written before the date;
//!   tested = rows written after it or undated. Fleet prevalence is a
//!   coordinate (a new entry that also exists on 39 other hosts is an update,
//!   one that exists nowhere else is not).
//! * **fleet** (no baseline, several hosts): reference = every row of the
//!   technique; tested = entries present on exactly one host, judged on
//!   folder, name shape and burst (being unique is the selection, not a
//!   coordinate, otherwise every unique entry would score the same).
//! * **none** (one host, no baseline): nothing can be compared with anything;
//!   the test is skipped and the run says so. Rules and stock lists still apply.
//!
//! Stock and known-good rows are reference, never tested.

use std::collections::{HashMap, HashSet};

use chrono::NaiveDateTime;

use super::normalize::{DirFamily, NameClass, Os, Row};
use super::stats;

/// One rarity coordinate of a row: its tail share and a human detail.
#[derive(Debug, Clone)]
pub struct Coordinate {
    pub name: &'static str,
    pub share: f64,
    pub detail: String,
}

/// What the test said about one row.
/// Why a row was, or was not, put to the statistical test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// No test for the row's operating system in this run (one host and no
    /// baseline), or nothing to compare the row with.
    #[default]
    NotEvaluated,
    /// Stock or known-good: reference, never tested.
    Exempt,
    /// Written before the baseline: reference.
    Baseline,
    /// Fleet mode, present on several hosts: reference.
    Shared,
    /// Put to the test.
    Tested,
}

#[derive(Debug, Clone)]
pub struct RowStat {
    pub index: usize,
    pub role: Role,
    pub t: f64,
    pub coords: Vec<Coordinate>,
    /// Hosts carrying this entry, hosts in the run (same OS), when there are several hosts.
    pub fleet: Option<(usize, usize)>,
    /// The row was put to the test (not reference-only, not exempt).
    pub tested: bool,
    pub p: f64,
    pub q: f64,
    pub significant: bool,
    /// Rows of the same technique the row was compared with.
    pub reference: usize,
}

impl RowStat {
    fn untested(index: usize) -> Self {
        RowStat { index, role: Role::NotEvaluated, t: 0.0, coords: Vec::new(), fleet: None, tested: false, p: 1.0, q: 1.0, significant: false, reference: 0 }
    }

    /// Coordinates that contributed (share below 1), most unusual first.
    pub fn unusual(&self) -> Vec<&Coordinate> {
        let mut v: Vec<&Coordinate> = self.coords.iter().filter(|c| c.share < 1.0).collect();
        v.sort_by(|a, b| a.share.partial_cmp(&b.share).unwrap_or(std::cmp::Ordering::Equal));
        v
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Baseline,
    Fleet,
    None,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Baseline => "baseline",
            Mode::Fleet => "fleet",
            Mode::None => "none",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RarityReport {
    pub hosts_windows: usize,
    pub hosts_linux: usize,
    pub mode_windows: Option<Mode>,
    pub mode_linux: Option<Mode>,
    pub groups: usize,
    pub tested: usize,
    pub significant: usize,
    /// Techniques whose tested rows had nothing to be compared with.
    pub no_reference: Vec<String>,
    pub smallest_p: f64,
}

/// Minute bucket of a timestamp, for the burst coordinate.
fn minute_of(ts: NaiveDateTime) -> i64 {
    ts.and_utc().timestamp() / 60
}

/// Compute rarity statistics for every row. `exempt[i]` marks rows that are
/// reference only (stock, known-good). `alpha` is the FDR level.
pub fn rarity(rows: &[Row], baseline: Option<NaiveDateTime>, exempt: &[bool], alpha: f64) -> (Vec<RowStat>, RarityReport) {
    let mut report = RarityReport { smallest_p: 1.0, ..Default::default() };
    let mut out: Vec<RowStat> = rows.iter().map(|r| RowStat::untested(r.index)).collect();
    if rows.is_empty() {
        return (out, report);
    }

    let hosts_of = |os: Os| rows.iter().filter(|r| r.os == os).map(|r| r.host.as_str()).collect::<HashSet<_>>().len();
    report.hosts_windows = hosts_of(Os::Windows);
    report.hosts_linux = hosts_of(Os::Linux);
    let mode_for = |hosts: usize| -> Mode {
        if baseline.is_some() {
            Mode::Baseline
        } else if hosts >= 2 {
            Mode::Fleet
        } else {
            Mode::None
        }
    };
    if report.hosts_windows > 0 {
        report.mode_windows = Some(mode_for(report.hosts_windows));
    }
    if report.hosts_linux > 0 {
        report.mode_linux = Some(mode_for(report.hosts_linux));
    }

    // burst: distinct techniques per (host, minute); per host the bucket size of each dated row
    let mut bucket_techs: HashMap<(&str, i64), HashSet<&str>> = HashMap::new();
    for r in rows {
        if let Some(ts) = r.ts {
            bucket_techs.entry((r.host.as_str(), minute_of(ts))).or_default().insert(r.technique.as_str());
        }
    }
    let mut host_bucket_sizes: HashMap<&str, Vec<usize>> = HashMap::new();
    for r in rows {
        if let Some(ts) = r.ts {
            let k = bucket_techs.get(&(r.host.as_str(), minute_of(ts))).map(|s| s.len()).unwrap_or(1);
            host_bucket_sizes.entry(r.host.as_str()).or_default().push(k);
        }
    }
    for v in host_bucket_sizes.values_mut() {
        v.sort_unstable();
    }

    let mut groups: HashMap<(Os, &str), Vec<usize>> = HashMap::new();
    for (i, r) in rows.iter().enumerate() {
        groups.entry((r.os, r.technique.as_str())).or_default().push(i);
    }
    report.groups = groups.len();

    let mut tested_ps: Vec<(usize, f64)> = Vec::new();
    let mut no_ref: Vec<String> = Vec::new();

    for ((os, technique), members) in &groups {
        let hosts_total = match os {
            Os::Windows => report.hosts_windows,
            Os::Linux => report.hosts_linux,
            Os::Unknown => 0,
        };
        let mode = mode_for(hosts_total);

        // hosts per entry, over every row of the technique
        let mut canon_hosts: HashMap<&str, HashSet<&str>> = HashMap::new();
        for &i in members {
            canon_hosts.entry(rows[i].canon.as_str()).or_default().insert(rows[i].host.as_str());
        }
        let hosts_with = |i: usize| canon_hosts.get(rows[i].canon.as_str()).map(|s| s.len()).unwrap_or(1);

        let is_reference = |i: usize| -> bool {
            match (mode, baseline) {
                (Mode::Baseline, Some(b)) => rows[i].ts.is_some_and(|t| t < b),
                _ => true,
            }
        };
        let is_tested = |i: usize| -> bool {
            if exempt.get(i).copied().unwrap_or(false) {
                return false;
            }
            match (mode, baseline) {
                (Mode::Baseline, Some(b)) => rows[i].ts.is_none_or(|t| t >= b),
                (Mode::Fleet, _) => hosts_with(i) == 1,
                _ => false,
            }
        };

        let reference: Vec<usize> = members.iter().copied().filter(|&i| is_reference(i)).collect();
        let n_ref = reference.len();
        let mut fam_count: HashMap<DirFamily, usize> = HashMap::new();
        let mut name_count: HashMap<NameClass, usize> = HashMap::new();
        for &i in &reference {
            *fam_count.entry(rows[i].family).or_default() += 1;
            *name_count.entry(rows[i].name_class).or_default() += 1;
        }

        let coords_of = |i: usize| -> Vec<Coordinate> {
            let r = &rows[i];
            let extra = usize::from(!is_reference(i));
            let n = n_ref + extra;
            let mut v = Vec::with_capacity(4);
            if mode == Mode::Baseline && hosts_total >= 2 {
                let h = hosts_with(i);
                v.push(Coordinate { name: "fleet", share: stats::share(h, hosts_total), detail: format!("on {h} of {hosts_total} hosts") });
            }
            if n > 0 {
                let mine = fam_count.get(&r.family).copied().unwrap_or(0) + extra;
                let tail: usize = fam_count.values().filter(|&&c| c <= mine).sum::<usize>() + extra;
                v.push(Coordinate { name: "folder", share: stats::share(tail.min(n), n), detail: format!("{} ({mine} of {n} {technique} rows)", r.family.label()) });
                let mine_n = name_count.get(&r.name_class).copied().unwrap_or(0) + extra;
                let tail_n: usize = name_count.values().filter(|&&c| c <= mine_n).sum::<usize>() + extra;
                v.push(Coordinate { name: "name", share: stats::share(tail_n.min(n), n), detail: format!("{} ({mine_n} of {n})", r.name_class.label()) });
            }
            if let Some(ts) = r.ts {
                let k = bucket_techs.get(&(r.host.as_str(), minute_of(ts))).map(|s| s.len()).unwrap_or(1);
                if k >= 2 {
                    if let Some(sizes) = host_bucket_sizes.get(r.host.as_str()) {
                        let at_least = sizes.len() - sizes.partition_point(|&s| s < k);
                        v.push(Coordinate {
                            name: "burst",
                            share: stats::share(at_least, sizes.len()),
                            detail: format!("{k} techniques written at {}", ts.format("%Y-%m-%d %H:%M")),
                        });
                    }
                }
            }
            v
        };
        let t_of = |coords: &[Coordinate]| -> f64 { coords.iter().map(|c| -c.share.ln()).sum::<f64>() };

        for &i in members {
            if hosts_total >= 2 {
                out[i].fleet = Some((hosts_with(i), hosts_total));
            }
            out[i].role = if exempt.get(i).copied().unwrap_or(false) {
                Role::Exempt
            } else {
                match (mode, baseline) {
                    (Mode::Baseline, Some(b)) if rows[i].ts.is_some_and(|t| t < b) => Role::Baseline,
                    (Mode::Fleet, _) if hosts_with(i) >= 2 => Role::Shared,
                    _ => Role::NotEvaluated,
                }
            };
        }

        let mut sorted_null: Vec<f64> = Vec::with_capacity(n_ref);
        for &i in &reference {
            let c = coords_of(i);
            out[i].t = t_of(&c);
            sorted_null.push(out[i].t);
            out[i].coords = c;
        }
        sorted_null.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        for &i in members {
            if !is_tested(i) {
                continue;
            }
            let in_ref = is_reference(i);
            if out[i].coords.is_empty() {
                let c = coords_of(i);
                out[i].t = t_of(&c);
                out[i].coords = c;
            }
            let others = n_ref - usize::from(in_ref);
            if others == 0 {
                if !no_ref.iter().any(|t| t == technique) {
                    no_ref.push(technique.to_string());
                }
                continue;
            }
            let t = out[i].t;
            let mut at_least = sorted_null.len() - sorted_null.partition_point(|v| *v < t);
            if in_ref {
                at_least = at_least.saturating_sub(1);
            }
            let p = stats::empirical_p(at_least, others);
            out[i].p = p;
            out[i].tested = true;
            out[i].role = Role::Tested;
            out[i].reference = others;
            tested_ps.push((i, p));
        }
    }

    // Benjamini-Hochberg across every tested row of the run
    let ps: Vec<f64> = tested_ps.iter().map(|x| x.1).collect();
    let qs = stats::benjamini_hochberg(&ps);
    for ((i, p), q) in tested_ps.iter().zip(qs) {
        out[*i].q = q;
        out[*i].significant = q <= alpha;
        if *p < report.smallest_p {
            report.smallest_p = *p;
        }
    }
    report.tested = tested_ps.len();
    report.significant = out.iter().filter(|s| s.significant).count();
    no_ref.sort();
    report.no_reference = no_ref;
    (out, report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::hunt::normalize::normalize;

    fn ev(host: &str, artifact: &str, cmd: &str, ts: &str) -> Event {
        Event {
            timestamp: ts.into(),
            computer: host.into(),
            artifact: artifact.into(),
            event_id: 0,
            pid: 0,
            subject_username: "System".into(),
            target_username: "System".into(),
            processname: String::new(),
            commandline: Some(cmd.into()),
            source_file: "x".into(),
        }
    }

    fn rows_of(events: &[Event]) -> Vec<Row> {
        events.iter().enumerate().map(|(i, e)| normalize(i, e)).collect()
    }

    fn baseline(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    /// 40 hosts with the same 30 services (20 from System32, 10 from Program Files);
    /// one host has one extra service from ProgramData with a hex name.
    fn fleet() -> Vec<Event> {
        let mut v = Vec::new();
        for h in 0..40 {
            for s in 0..30 {
                let cmd = if s % 3 == 0 { format!("\"C:\\Program Files\\Vendor{s}\\svc.exe\" -k g{s}") } else { format!("C:\\Windows\\system32\\svc{s}.exe -k g{s}") };
                v.push(ev(
                    &format!("H{h:02}"),
                    "windows:persistence:windows_service",
                    &cmd,
                    &format!("2026-01-{:02} 10:{:02}:00.000", 1 + s % 20, s),
                ));
            }
        }
        v.push(ev("H07", "windows:persistence:windows_service", "C:\\ProgramData\\deadbeef01.exe", "2026-10-05 03:12:00.000"));
        v
    }

    #[test]
    fn fleet_mode_tests_unique_entries_only() {
        let events = fleet();
        let rows = rows_of(&events);
        let exempt = vec![false; rows.len()];
        let (stats, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.hosts_windows, 40);
        assert_eq!(report.mode_windows, Some(Mode::Fleet));
        assert_eq!(report.tested, 1);
        let last = stats.last().unwrap();
        assert!(last.tested);
        assert!(last.significant, "p={} q={}", last.p, last.q);
        assert_eq!(last.fleet, Some((1, 40)));
        assert!(last.coords.iter().all(|c| c.name != "fleet"));
        assert!(last.unusual().iter().any(|c| c.name == "folder"));
        assert!(last.unusual().iter().any(|c| c.name == "name"));
        assert_eq!(report.significant, 1);
        assert!(stats[..stats.len() - 1].iter().all(|s| !s.tested && s.fleet == Some((40, 40))));
    }

    #[test]
    fn baseline_mode_tests_new_rows_with_fleet_coordinate() {
        let events = fleet();
        let rows = rows_of(&events);
        let exempt = vec![false; rows.len()];
        let (stats, report) = rarity(&rows, Some(baseline("2026-06-01 00:00:00")), &exempt, 0.05);
        assert_eq!(report.mode_windows, Some(Mode::Baseline));
        assert_eq!(report.tested, 1);
        let last = stats.last().unwrap();
        assert!(last.significant);
        assert!(last.coords.iter().any(|c| c.name == "fleet" && c.share < 0.05));
        assert!(stats[..stats.len() - 1].iter().all(|s| !s.tested));
    }

    #[test]
    fn a_plain_unique_entry_is_not_significant_when_many_are_unique() {
        // every host has its own vendor service in Program Files: unique, but ordinary
        let mut events = fleet();
        for h in 0..40 {
            events.push(ev(&format!("H{h:02}"), "windows:persistence:windows_service", &format!("\"C:\\Program Files\\Vendor{h}\\agent.exe\""), "2026-01-03 09:00:00.000"));
        }
        let rows = rows_of(&events);
        let exempt = vec![false; rows.len()];
        let (stats, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.tested, 41);
        // the vendor agents: not significant; the ProgramData hex one: still is
        let idx_outlier = 1200;
        assert!(stats[idx_outlier].significant, "p={} q={}", stats[idx_outlier].p, stats[idx_outlier].q);
        assert!(stats[1201..].iter().all(|s| s.tested && !s.significant), "{:?}", stats[1201].q);
    }

    #[test]
    fn exempt_rows_are_reference_only() {
        let events = fleet();
        let rows = rows_of(&events);
        let mut exempt = vec![true; rows.len()];
        *exempt.last_mut().unwrap() = false;
        let (stats, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.tested, 1);
        assert!(stats.last().unwrap().significant);
        let exempt = vec![true; rows.len()];
        let (_, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.tested, 0);
    }

    #[test]
    fn nothing_flagged_on_a_uniform_fleet() {
        let mut events = fleet();
        events.pop();
        let rows = rows_of(&events);
        let exempt = vec![false; rows.len()];
        let (_, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.tested, 0);
        assert_eq!(report.significant, 0);
    }

    fn single_host() -> Vec<Event> {
        let mut v = Vec::new();
        for s in 0..60 {
            v.push(ev("ONLY", "windows:persistence:windows_service", &format!("C:\\Windows\\system32\\svc{s}.exe"), &format!("2026-01-01 10:{:02}:00.000", s % 60)));
        }
        v.push(ev("ONLY", "windows:persistence:windows_service", "C:\\Users\\Public\\a1b2c3d4e5.exe", "2026-03-01 03:00:00.000"));
        v
    }

    #[test]
    fn single_host_without_baseline_tests_nothing() {
        let rows = rows_of(&single_host());
        let exempt = vec![false; rows.len()];
        let (stats, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.hosts_windows, 1);
        assert_eq!(report.mode_windows, Some(Mode::None));
        assert_eq!(report.tested, 0);
        assert!(stats.iter().all(|s| !s.tested && s.fleet.is_none()));
    }

    #[test]
    fn single_host_with_baseline_tests_the_new_row() {
        let rows = rows_of(&single_host());
        let exempt = vec![false; rows.len()];
        let (stats, report) = rarity(&rows, Some(baseline("2026-02-01 00:00:00")), &exempt, 0.05);
        assert_eq!(report.tested, 1);
        let last = stats.last().unwrap();
        assert!(last.coords.iter().all(|c| c.name != "fleet"));
        assert!(last.significant, "p={} q={}", last.p, last.q);
        assert_eq!(last.reference, 60);
    }

    #[test]
    fn burst_coordinate_counts_distinct_techniques() {
        let mut v = Vec::new();
        for s in 0..40 {
            v.push(ev("H", "windows:persistence:windows_service", &format!("C:\\Windows\\system32\\svc{s}.exe"), &format!("2026-01-{:02} 10:00:00.000", 1 + s % 28)));
            v.push(ev("H", "windows:persistence:registry_run_key", &format!("C:\\Program Files\\v{s}\\v.exe"), &format!("2026-02-{:02} 11:00:00.000", 1 + s % 28)));
        }
        v.push(ev("H", "windows:persistence:windows_service", "C:\\Windows\\system32\\upd.exe", "2026-10-05 03:12:10.000"));
        v.push(ev("H", "windows:persistence:registry_run_key", "C:\\Program Files\\upd\\upd.exe", "2026-10-05 03:12:40.000"));
        v.push(ev("H", "windows:persistence:scheduled_task", "C:\\Program Files\\upd\\upd.exe", "2026-10-05 03:12:55.000"));
        let rows = rows_of(&v);
        let exempt = vec![false; rows.len()];
        let (stats, _) = rarity(&rows, Some(baseline("2026-06-01 00:00:00")), &exempt, 0.05);
        let s = &stats[stats.len() - 3];
        let burst = s.coords.iter().find(|c| c.name == "burst").expect("burst coordinate");
        assert!(burst.detail.starts_with("3 techniques"));
        assert!(burst.share < 0.1, "{}", burst.share);
        assert!(s.significant, "p={} q={}", s.p, s.q);
    }

    #[test]
    fn no_reference_is_reported() {
        let v = vec![ev("H", "windows:persistence:appinit_dlls", "C:\\x\\h.dll", "2026-10-05 03:12:00.000")];
        let rows = rows_of(&v);
        let (stats, report) = rarity(&rows, Some(baseline("2026-06-01 00:00:00")), &[false], 0.05);
        assert!(!stats[0].tested);
        assert_eq!(report.no_reference, vec!["appinit_dlls".to_string()]);
    }

    #[test]
    fn linux_and_windows_hosts_are_counted_apart() {
        let mut v = fleet();
        v.push(ev("LNX", "linux:cron:system_job", "System Cron: /usr/bin/x (File: /etc/crontab)", "2026-01-01 00:00:00.000"));
        let rows = rows_of(&v);
        let exempt = vec![false; rows.len()];
        let (stats, report) = rarity(&rows, None, &exempt, 0.05);
        assert_eq!(report.hosts_linux, 1);
        assert_eq!(report.mode_linux, Some(Mode::None));
        assert!(!stats.last().unwrap().tested);
        assert_eq!(report.tested, 1);
    }

    #[test]
    fn empty_input() {
        let (s, r) = rarity(&[], None, &[], 0.05);
        assert!(s.is_empty());
        assert_eq!(r.tested, 0);
        assert!(r.mode_windows.is_none());
    }
}
