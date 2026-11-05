//! Hunting: every timeline row gets masstin's analysis tail, `hunt`,
//! `hunt_score` and `hunt_why` (`verdict` and `notes` stay the analyst's).
//!
//! Two engines look at each row:
//!
//! * **knowledge** ([`rules`]) — what known-bad persistence looks like
//!   (LOLBins with URLs, encoded PowerShell, `ld.so.preload`, reverse
//!   shells, scratch folders, system names outside their folders…), and
//!   what a stock system ships with ([`known_good`]), plus the analyst's
//!   own clean CSVs (`--known-good`);
//! * **statistics** ([`rarity`]) — how unusual the row is compared with the
//!   rows of the same technique in this run: on how many hosts it appears,
//!   how common its folder and its name shape are, whether it was written
//!   in a burst with other techniques. Calibrated against the run's own
//!   rows, Benjamini-Hochberg across the run; the only chosen number is
//!   `--alpha`.
//!
//! `--baseline <date>`: rows written before it are the reference (what the
//! machine looked like when it was trusted); rows after it are the ones put
//! to the test, and are `candidate` when nothing else is said about them.
//!
//! `hunt` takes the six words masstin, caarea, faramir and allymacb share
//! (masstin's `docs/csv-format.md`, "The same tail in caarea, faramir and
//! allymacb"): `significant`, `candidate`, `habitual`, `baseline`,
//! `not_evaluated`, or empty with `--no-hunt`. The state comes from the
//! strongest evidence: a high rule gives `significant`, a medium rule
//! `candidate`, a low rule leaves the statistical state as it is; when a test
//! and a rule both speak, the stronger state wins. `hunt_why` says which
//! spoke: a rule's clause starts with `rule <id> (<level>): `, the test's
//! clause is in words. `suspicious` is the analyst's word, in `verdict`.

pub mod known_good;
pub mod marks;
pub mod measured;
pub mod normalize;
pub mod rarity;
pub mod rules;
pub mod stats;

use std::path::PathBuf;

use chrono::{NaiveDate, NaiveDateTime};

use crate::errors::FaramirError;
use crate::event::Event;
use crate::windows::diag;

pub use known_good::KnownGood;
pub use marks::Marks;
pub use normalize::{normalize, Row, State};
pub use rules::{Level, Rule, RULES};

/// Default false-discovery rate.
pub const DEFAULT_ALPHA: f64 = 0.05;

/// The `hunt` column: the six words of the shared tail, no others. Highest
/// wins when several apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Hunt {
    /// Hunting off.
    #[default]
    None,
    /// No test could be made of the row (one host and no baseline, or
    /// nothing to compare it with) and no rule fired.
    NotEvaluated,
    /// Written before `--baseline`: reference, not judged.
    Baseline,
    /// Stock entry, in a known-good CSV, or present on several hosts of
    /// the fleet: p = 1.
    Habitual,
    /// New and tested with q above alpha, no longer on the live system, or
    /// a medium rule on an entry nothing vouches for: nothing passes the
    /// bar, but worth a look.
    Candidate,
    /// Tested with q at or below alpha, or a high rule fired.
    Significant,
}

impl Hunt {
    pub const ALL: [Hunt; 6] = [Hunt::None, Hunt::NotEvaluated, Hunt::Baseline, Hunt::Habitual, Hunt::Candidate, Hunt::Significant];

    pub fn label(self) -> &'static str {
        match self {
            Hunt::None => "",
            Hunt::NotEvaluated => "not_evaluated",
            Hunt::Baseline => "baseline",
            Hunt::Habitual => "habitual",
            Hunt::Candidate => "candidate",
            Hunt::Significant => "significant",
        }
    }

    pub fn parse(s: &str) -> Option<Hunt> {
        let s = s.trim().to_ascii_lowercase();
        Hunt::ALL.iter().copied().find(|h| h.label() == s)
    }
}

/// The hunt's verdict on one row: the three columns it writes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Verdict {
    pub hunt: Hunt,
    /// `hunt_score`, 0–100: masstin's rarity, with the rules' evidence added
    /// in the same unit (see [`score_for`]).
    pub score: u8,
    /// q-value when the row was tested; 1 when habitual; None otherwise.
    pub q: Option<f64>,
    pub reasons: Vec<String>,
}

impl Verdict {
    /// The `hunt_score` column: empty only when the hunt was off.
    pub fn hunt_score(&self) -> String {
        if self.hunt == Hunt::None {
            String::new()
        } else {
            self.score.to_string()
        }
    }

    /// The `hunt_why` column: the rules first (`rule <id> (<level>): …`,
    /// strongest first), then the test and the rest in words, `; ` between.
    pub fn hunt_why(&self) -> String {
        self.reasons.join("; ")
    }
}

/// Rarity in masstin's unit: −10·log10(q). 0 for q ≥ 1, 100 for q ≤ 0.
/// Ten points are one order of magnitude.
pub fn rarity_points(q: f64) -> f64 {
    if q.is_nan() || q >= 1.0 {
        0.0
    } else if q <= 0.0 {
        100.0
    } else {
        (-10.0 * q.log10()).min(100.0)
    }
}

/// The evidence a row carries, for the score.
#[derive(Debug, Clone, Copy, Default)]
pub struct Evidence {
    /// Rule points: the measured rarity of every rule that counts on the
    /// row's system ([`measured::points`]), summed.
    pub rule_points: u32,
    pub tested: bool,
    pub q: f64,
}

/// `hunt_score`, masstin's definition: −10·log10 of how rare the row is,
/// rounded, 0 to 100. The statistical test gives its q-value; every rule
/// that fired adds the rarity measured for it on clean rows of the row's
/// system ([`measured`]), since independent evidence adds in log space. A
/// reference row (`habitual`, `baseline`) is 0: p = 1, not judged.
///
/// Read as masstin reads it: 0 no rarer than chance, 13 one in twenty (the
/// default alpha), 20 one in a hundred, 29 a rule that never fired on the
/// reference (the bound 750 rows give), 30 one in a thousand, 60 one in a
/// million, 100 the cap.
pub fn score_for(hunt: Hunt, e: &Evidence) -> u8 {
    match hunt {
        Hunt::Habitual | Hunt::Baseline | Hunt::None => 0,
        _ => {
            let stat = if e.tested { rarity_points(e.q) } else { 0.0 };
            (stat + e.rule_points as f64).round().clamp(0.0, 100.0) as u8
        }
    }
}

#[derive(Debug, Clone)]
pub struct HuntSettings {
    pub enabled: bool,
    pub baseline: Option<NaiveDateTime>,
    pub alpha: f64,
    pub known_good: Vec<PathBuf>,
}

impl Default for HuntSettings {
    fn default() -> Self {
        HuntSettings { enabled: true, baseline: None, alpha: DEFAULT_ALPHA, known_good: Vec::new() }
    }
}

#[derive(Debug, Default, Clone)]
pub struct HuntReport {
    pub rows: usize,
    /// Rows made `significant` by a high rule.
    pub rule_high: usize,
    /// Rows made `candidate` by a medium rule.
    pub rule_medium: usize,
    pub significant: usize,
    pub candidate: usize,
    pub habitual: usize,
    pub baseline: usize,
    pub not_evaluated: usize,
    pub clean: usize,
    pub stock: usize,
    /// Rows the clean reference hosts carry.
    pub reference: usize,
    pub known_good: usize,
    pub after_baseline: usize,
    pub hosts: usize,
    pub tested: usize,
    /// Tested rows with q at or below alpha.
    pub passed: usize,
    pub no_reference: Vec<String>,
    pub mode_windows: Option<rarity::Mode>,
    pub mode_linux: Option<rarity::Mode>,
}

impl HuntReport {
    /// One line for the console and the diagnostics.
    pub fn summary_line(&self) -> String {
        format!(
            "{} row(s): {} significant ({} by a high rule), {} candidate ({} by a medium rule), {} habitual, {} baseline, {} not evaluated; {} stock, {} on the clean reference, {} known-good; {} host(s), {} tested statistically, {} at or below alpha",
            self.rows,
            self.significant,
            self.rule_high,
            self.candidate,
            self.rule_medium,
            self.habitual,
            self.baseline,
            self.not_evaluated,
            self.stock,
            self.reference,
            self.known_good,
            self.hosts,
            self.tested,
            self.passed
        )
    }
}

/// `YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, `YYYY-MM-DD HH:MM:SS` or ISO `T` forms.
pub fn parse_baseline(s: &str) -> Result<NaiveDateTime, FaramirError> {
    let t = s.trim();
    for f in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(t.trim_end_matches('Z'), f) {
            return Ok(dt);
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).ok_or_else(|| FaramirError::HuntBaselineInvalid(s.to_string()));
    }
    Err(FaramirError::HuntBaselineInvalid(s.to_string()))
}

pub fn validate_alpha(alpha: f64) -> Result<f64, FaramirError> {
    if alpha.is_finite() && alpha > 0.0 && alpha < 1.0 {
        Ok(alpha)
    } else {
        Err(FaramirError::HuntAlphaInvalid(format!("{alpha}")))
    }
}

/// Evaluate every event. The verdicts line up with `events` by position.
pub fn evaluate(events: &[Event], settings: &HuntSettings) -> (Vec<Verdict>, HuntReport) {
    let mut report = HuntReport { rows: events.len(), ..Default::default() };
    if !settings.enabled {
        diag::record(FaramirError::HuntDisabled("--no-hunt: hunt, hunt_score and hunt_why are left empty".into()));
        return (vec![Verdict::default(); events.len()], report);
    }
    let rows: Vec<Row> = events.iter().enumerate().map(|(i, e)| normalize(i, e)).collect();

    let (kg, kg_errors) = KnownGood::load(&settings.known_good);
    let kg = kg.with_reference();
    for e in kg_errors {
        diag::record(e);
    }

    // timestamps present but not parseable
    let unparsed = events.iter().zip(&rows).filter(|(e, r)| !e.timestamp.trim().is_empty() && r.ts.is_none() && !e.timestamp.starts_with("1970-01-01")).count();
    if unparsed > 0 {
        diag::record(FaramirError::HuntTimestampUnparsed(format!("{unparsed} row(s)")));
    }

    let stock: Vec<Option<&'static str>> = rows.iter().map(known_good::stock_reason).collect();
    let in_kg: Vec<Option<&'static str>> = rows.iter().map(|r| kg.reason(r)).collect();
    let exempt: Vec<bool> = stock.iter().zip(&in_kg).map(|(s, k)| s.is_some() || k.is_some()).collect();
    let matched: Vec<Vec<&'static Rule>> = rows.iter().map(rules::matching).collect();

    let (stats, rar) = rarity::rarity(&rows, settings.baseline, &exempt, settings.alpha);
    report.hosts = rar.hosts_windows + rar.hosts_linux;
    report.tested = rar.tested;
    report.passed = rar.significant;
    report.no_reference = rar.no_reference.clone();
    report.mode_windows = rar.mode_windows;
    report.mode_linux = rar.mode_linux;
    for (os, hosts, mode) in [("Windows", rar.hosts_windows, rar.mode_windows), ("Linux", rar.hosts_linux, rar.mode_linux)] {
        if hosts == 1 {
            diag::record(FaramirError::HuntSingleHost(match mode {
                Some(rarity::Mode::None) => format!("{os}: no --baseline, the statistical test is skipped (rules and stock lists still apply); give --baseline <date> or several hosts"),
                _ => format!("{os}: fleet prevalence not measured, rows are tested against the rows before the baseline"),
            }));
        }
    }
    if !rar.no_reference.is_empty() {
        diag::record(FaramirError::HuntNoReference(rar.no_reference.join(", ")));
    }

    let mut verdicts = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let mut reasons: Vec<String> = Vec::new();
        let mut points: u32 = 0;
        // strongest rule first; catalogue order within a level. A rule measured
        // common on this system is noise: its clause stays, it adds no points
        // and does not speak for the state.
        let mut fired = matched[i].clone();
        fired.sort_by_key(|r| std::cmp::Reverse(r.level));
        let counting: Vec<&'static Rule> = fired.iter().copied().filter(|r| measured::counts(r.id, row.os)).collect();
        // an entry a clean host carries, or the analyst's known-good CSV: its
        // rules keep their clause and add nothing
        let clean = in_kg[i].is_some();
        if !clean {
            for rule in &counting {
                points += measured::points(rule.id, row.os);
            }
        }
        for rule in &fired {
            reasons.push(format!("rule {} ({}): {} [{}]", rule.id, rule.level.label(), rule.title, rule.attack));
        }
        let mut ev = Evidence { rule_points: points, ..Default::default() };
        let vouched = exempt[i];
        let st = &stats[i];
        let after_baseline = settings.baseline.is_some_and(|b| row.ts.is_none_or(|t| t >= b)) && row.state == State::Live;
        let review_floor = (after_baseline && !vouched) || (row.state != State::Live && !clean);

        // what the statistics (and the row's state) say
        let by_test = if st.significant {
            Hunt::Significant
        } else if review_floor || st.tested {
            Hunt::Candidate
        } else if vouched || st.role == rarity::Role::Shared {
            Hunt::Habitual
        } else if st.role == rarity::Role::Baseline {
            Hunt::Baseline
        } else {
            Hunt::NotEvaluated
        };
        // what the rules say: a high rule is `significant` whatever the stock
        // pattern list says; a medium rule is `candidate` unless the entry is
        // stock; a low rule leaves the test's state alone, and on a row no
        // test judged it gives `candidate`, so a score never comes without a
        // state. An entry the clean reference hosts or the known-good CSV
        // carry is vouched for by identity: no rule changes its state.
        let strongest = counting.first().map(|r| r.level);
        let by_rule = match strongest {
            _ if clean => None,
            Some(Level::High) => Some(Hunt::Significant),
            Some(Level::Medium) if !vouched => Some(Hunt::Candidate),
            Some(Level::Low) if !vouched && by_test == Hunt::NotEvaluated => Some(Hunt::Candidate),
            _ => None,
        };
        // the stronger state wins
        let hunt = by_rule.map_or(by_test, |r| r.max(by_test));
        match (strongest, by_rule) {
            (Some(Level::High), _) => report.rule_high += 1,
            (Some(Level::Medium), Some(Hunt::Candidate)) => report.rule_medium += 1,
            _ => {}
        }
        let q = if st.tested {
            Some(st.q)
        } else if vouched || st.role == rarity::Role::Shared {
            Some(1.0)
        } else {
            None
        };

        ev.tested = st.tested;
        ev.q = st.q;
        if st.significant {
            let mut detail: Vec<String> = Vec::new();
            if let Some((h, n)) = st.fleet {
                if !st.coords.iter().any(|c| c.name == "fleet") {
                    detail.push(format!("on {h} of {n} hosts"));
                }
            }
            detail.extend(st.unusual().iter().map(|c| format!("{}: {}", c.name, c.detail)));
            reasons.push(format!("rare among {} {} row(s) (p={:.3}, q={:.3}): {}", st.reference, row.technique, st.p, st.q, detail.join(", ")));
        } else if st.tested {
            // only mention the strongest unusual coordinate when a rule flagged the row
            if by_rule.is_some() {
                if let Some(c) = st.unusual().first() {
                    reasons.push(format!("{}: {}", c.name, c.detail));
                }
            }
        }
        if review_floor {
            if row.state != State::Live {
                reasons.push(row.state.label().to_string());
            }
            if after_baseline && !vouched {
                reasons.push(match row.ts {
                    Some(_) => "written after the baseline".to_string(),
                    None => "undated".to_string(),
                });
            }
        }
        if after_baseline {
            report.after_baseline += 1;
        }
        if let Some(s) = stock[i] {
            reasons.push(s.to_string());
            report.stock += 1;
        }
        if let Some(why) = in_kg[i] {
            reasons.push(why.to_string());
            if why == known_good::REFERENCE_REASON {
                report.reference += 1;
            } else {
                report.known_good += 1;
            }
        }
        match st.role {
            rarity::Role::Baseline => reasons.push("before the baseline".to_string()),
            rarity::Role::Shared => {
                if let Some((h, n)) = st.fleet {
                    reasons.push(format!("on {h} of {n} hosts"));
                }
            }
            rarity::Role::NotEvaluated if hunt == Hunt::NotEvaluated => {
                let mode = match row.os {
                    normalize::Os::Linux => rar.mode_linux,
                    _ => rar.mode_windows,
                };
                reasons.push(match mode {
                    Some(rarity::Mode::None) => "not evaluated: one host and no baseline".to_string(),
                    _ => format!("not evaluated: no other {} row to compare with", row.technique),
                });
            }
            _ => {}
        }
        match hunt {
            Hunt::Significant => report.significant += 1,
            Hunt::Candidate => report.candidate += 1,
            Hunt::Habitual => report.habitual += 1,
            Hunt::Baseline => report.baseline += 1,
            Hunt::NotEvaluated => report.not_evaluated += 1,
            Hunt::None => report.clean += 1,
        }
        verdicts.push(Verdict { hunt, score: score_for(hunt, &ev), q, reasons });
    }
    if report.after_baseline > 0 {
        diag::record(FaramirError::HuntAfterBaseline(format!("{} row(s)", report.after_baseline)));
    }
    diag::record(FaramirError::HuntSummary(report.summary_line()));
    (verdicts, report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::normalize::Os;

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

    #[test]
    fn a_known_good_entry_is_habitual_whatever_its_rules() {
        diag::clear();
        let dir = std::env::temp_dir().join(format!("faramir_kg_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("clean.csv");
        std::fs::write(&csv, "event_type,detail\nwindows:persistence:registry_run_key,\"mshta http://x/a.hta\"\n").unwrap();
        let events = vec![
            ev("H", "windows:persistence:registry_run_key", "mshta http://x/a.hta", "2026-10-28 12:00:00.000"),
            ev("H", "windows:persistence:registry_run_key", "mshta http://y/b.hta", "2026-10-28 12:00:00.000"),
        ];
        let settings = HuntSettings { known_good: vec![csv.clone()], ..HuntSettings::default() };
        let (v, report) = evaluate(&events, &settings);
        assert_eq!(v[0].hunt, Hunt::Habitual, "{:?}", v[0]);
        assert_eq!(v[0].score, 0);
        assert!(v[0].hunt_why().starts_with("rule H") && v[0].hunt_why().ends_with(known_good::CSV_REASON), "{}", v[0].hunt_why());
        assert_eq!(v[1].hunt, Hunt::Significant, "the same high rule on an entry nothing vouches for: {:?}", v[1]);
        assert_eq!(report.known_good, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_parsing() {
        assert!(parse_baseline("2026-10-01").is_ok());
        assert!(parse_baseline("2026-10-01 13:45").is_ok());
        assert!(parse_baseline("2026-10-01 13:45:10").is_ok());
        assert!(parse_baseline("2026-10-01T13:45:10Z").is_ok());
        assert_eq!(parse_baseline("01/10/2026").unwrap_err().error_number(), 7001);
        assert_eq!(parse_baseline("").unwrap_err().error_number(), 7001);
        assert_eq!(validate_alpha(0.0).unwrap_err().error_number(), 7002);
        assert_eq!(validate_alpha(1.0).unwrap_err().error_number(), 7002);
        assert_eq!(validate_alpha(f64::NAN).unwrap_err().error_number(), 7002);
        assert!(validate_alpha(0.05).is_ok());
    }

    #[test]
    fn hunt_states_order_and_labels() {
        assert_eq!(Hunt::ALL.len(), 6, "the six words of the shared tail, no others");
        assert!(Hunt::Significant > Hunt::Candidate);
        assert!(Hunt::Candidate > Hunt::Habitual);
        assert!(Hunt::Habitual > Hunt::Baseline);
        assert!(Hunt::Baseline > Hunt::NotEvaluated);
        assert!(Hunt::NotEvaluated > Hunt::None);
        assert_eq!(Hunt::parse("SIGNIFICANT"), Some(Hunt::Significant));
        assert_eq!(Hunt::parse(""), Some(Hunt::None));
        assert_eq!(Hunt::parse("not_evaluated"), Some(Hunt::NotEvaluated));
        assert_eq!(Hunt::parse("weird"), None);
        for w in ["review", "malicious", "suspicious", "alert", "anomalous"] {
            assert_eq!(Hunt::parse(w), None, "{w} is not a word of the shared tail");
        }
        for h in Hunt::ALL {
            assert_eq!(Hunt::parse(h.label()), Some(h));
        }
        // masstin's words, spelled the same
        for w in ["significant", "candidate", "habitual", "not_evaluated", "baseline"] {
            assert!(Hunt::parse(w).is_some(), "{w}");
        }
    }

    #[test]
    fn hunt_score_and_hunt_why_text() {
        let v = Verdict { hunt: Hunt::Significant, score: 42, q: Some(0.012345), reasons: vec!["rare".into(), "x".into()] };
        assert_eq!(v.hunt_score(), "42");
        assert_eq!(v.hunt_why(), "rare; x");
        let v = Verdict { hunt: Hunt::Habitual, score: 0, q: Some(1.0), reasons: vec!["stock Linux entry".into()] };
        assert_eq!(v.hunt_score(), "0");
        assert_eq!(v.hunt_why(), "stock Linux entry");
        assert_eq!(Verdict::default().hunt_score(), "", "hunt off");
        assert_eq!(Verdict::default().hunt_why(), "");
    }

    #[test]
    fn rarity_points_are_masstins_decibans() {
        assert_eq!(rarity_points(1.0), 0.0);
        assert_eq!(rarity_points(2.0), 0.0);
        assert!((rarity_points(0.05) - 13.01).abs() < 0.01);
        assert!((rarity_points(0.01) - 20.0).abs() < 1e-9);
        assert!((rarity_points(0.001) - 30.0).abs() < 1e-9);
        assert!((rarity_points(1e-6) - 60.0).abs() < 1e-9);
        assert_eq!(rarity_points(1e-12), 100.0);
        assert_eq!(rarity_points(0.0), 100.0);
        assert_eq!(rarity_points(f64::NAN), 0.0);
    }

    #[test]
    fn score_is_masstins_rarity_plus_the_rules() {
        let e = |rule_points, tested, q| Evidence { rule_points, tested, q };
        // the statistics alone, exactly masstin's number
        assert_eq!(score_for(Hunt::Significant, &e(0, true, 0.05)), 13);
        assert_eq!(score_for(Hunt::Significant, &e(0, true, 0.001)), 30);
        assert_eq!(score_for(Hunt::Significant, &e(0, true, 1e-6)), 60);
        assert_eq!(score_for(Hunt::Significant, &e(0, true, 1e-12)), 100);
        assert_eq!(score_for(Hunt::Candidate, &e(0, true, 0.2)), 7);
        assert_eq!(score_for(Hunt::Candidate, &e(0, true, 1.0)), 0);
        assert_eq!(score_for(Hunt::Candidate, &e(0, false, 1.0)), 0, "deleted, nothing else: nothing to say in numbers");
        // the rules alone: their measured points, whatever the level
        assert_eq!(score_for(Hunt::Significant, &e(29, false, 1.0)), 29);
        assert_eq!(score_for(Hunt::Candidate, &e(24, false, 1.0)), 24);
        assert_eq!(score_for(Hunt::Candidate, &e(10, false, 1.0)), 10);
        assert_eq!(score_for(Hunt::NotEvaluated, &e(10, false, 1.0)), 10);
        // both add, in log space, and cap at 100
        assert_eq!(score_for(Hunt::Significant, &e(90, true, 0.05)), 100);
        assert_eq!(score_for(Hunt::Significant, &e(90 + 20 + 10, false, 1.0)), 100);
        assert_eq!(score_for(Hunt::Candidate, &e(20 + 10, true, 0.1)), 40);
        assert_eq!(score_for(Hunt::Significant, &e(10, true, 0.01)), 30);
        // reference rows are 0 whatever fired
        for h in [Hunt::Habitual, Hunt::Baseline, Hunt::None] {
            assert_eq!(score_for(h, &e(90, true, 0.001)), 0, "{h:?}");
        }
        // a rule's points survive a test with q = 1
        assert_eq!(score_for(Hunt::Significant, &e(29, true, 1.0)), 29);
        assert_eq!(score_for(Hunt::Candidate, &e(24, true, 1.0)), 24);
    }

    #[test]
    fn high_rule_stock_candidate_and_baseline() {
        diag::clear();
        let b = parse_baseline("2026-10-01").unwrap();
        let events = vec![
            ev("H", "windows:persistence:registry_run_key", "mshta http://x/a.hta", "2026-10-28 12:00:00.000"),
            ev("H", "windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe", "2026-10-28 12:00:00.000"),
            ev("H", "windows:persistence:registry_run_key", "\"C:\\Program Files\\Vendor\\tool.exe\" /tray", "2026-10-28 12:00:00.000"),
            ev("H", "windows:persistence:registry_run_key", "\"C:\\Program Files\\Vendor\\old.exe\" /tray", "2026-01-28 12:00:00.000"),
            ev("H", "windows:persistence:deleted:registry_run_key", "C:\\Windows\\system32\\gone.exe", ""),
        ];
        let (v, r) = evaluate(&events, &HuntSettings { baseline: Some(b), ..Default::default() });
        assert_eq!(v[0].hunt, Hunt::Significant, "a high rule writes significant");
        assert!(v[0].score >= 29, "H1001 never fired on the Windows reference: the bound it gives: {:?}", v[0]);
        assert!(v[0].reasons[0].starts_with("rule H1001 (high): "), "{:?}", v[0].reasons);
        let why = v[0].hunt_why();
        assert!(why.ends_with("; written after the baseline"), "{why}");
        let clauses: Vec<&str> = why.split("; ").collect();
        let rules = clauses.iter().take_while(|c| c.starts_with("rule ")).count();
        assert!(rules >= 1 && clauses[rules..].iter().all(|c| !c.starts_with("rule ")), "rules first, then the words: {why}");
        assert_eq!(v[1].hunt, Hunt::Habitual, "{:?}", v[1]);
        assert_eq!(v[1].hunt_score(), "0");
        assert!(v[1].reasons.iter().any(|x| x == "stock Windows entry"));
        assert_eq!(v[2].hunt, Hunt::Candidate);
        assert!(v[2].reasons.iter().any(|x| x == "written after the baseline"));
        assert_eq!(v[3].hunt, Hunt::Baseline, "{:?}", v[3]);
        assert_eq!(v[3].score, 0);
        assert!(v[2].score < 13, "candidate, q above alpha: {:?}", v[2]);
        assert_eq!(v[4].score, measured::points("H3014", Os::Windows) as u8, "deleted: the low rule H3014, its measured points: {:?}", v[4]);
        assert!(v[3].reasons.iter().any(|x| x == "before the baseline"));
        assert_eq!(v[4].hunt, Hunt::Candidate);
        assert!(v[4].reasons.iter().any(|x| x == "deleted"));
        assert_eq!(r.significant, 1);
        assert_eq!(r.rule_high, 1);
        assert_eq!(r.rule_medium, 0);
        assert_eq!(r.candidate, 2);
        assert_eq!(r.habitual, 1);
        assert_eq!(r.baseline, 1);
        assert_eq!(r.stock, 1);
        assert!(diag::has("ERR_HUNT_SUMMARY"));
        assert!(diag::has("ERR_HUNT_AFTER_BASELINE"));
    }

    #[test]
    fn rules_write_the_shared_words_and_say_so_in_hunt_why() {
        diag::clear();
        let events = vec![ev("H", "windows:persistence:scheduled_task", "powershell -nop -w hidden -File C:\\Users\\bob\\Documents\\a.ps1", "2026-10-28 12:00:00.000")];
        let (v, r) = evaluate(&events, &HuntSettings::default());
        // H1002 medium + H1009 high + H3003 medium -> significant because of the high, which comes first
        assert_eq!(v[0].hunt, Hunt::Significant, "{:?}", v[0]);
        assert!(v[0].reasons[0].starts_with("rule H1009 (high): "), "strongest rule first: {:?}", v[0].reasons);
        assert!(v[0].reasons[1].starts_with("rule H") && v[0].reasons[1].contains(" (medium): "), "{:?}", v[0].reasons);
        let ids: Vec<String> = v[0].reasons.iter().filter_map(|r| r.strip_prefix("rule ")).map(|r| r.split(' ').next().unwrap().to_string()).collect();
        assert!(ids.len() >= 3, "{ids:?}");
        let expected: u32 = ids.iter().map(|id| measured::points(id, Os::Windows)).sum();
        assert_eq!(v[0].score as u32, expected.min(100), "{ids:?}");
        assert_eq!(r.rule_high, 1);
        // a medium rule alone: candidate, its measured points
        let events = vec![ev("H", "windows:persistence:registry_run_key", "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --tray", "2026-10-28 12:00:00.000")];
        let (v, r) = evaluate(&events, &HuntSettings::default());
        assert_eq!(v[0].hunt, Hunt::Candidate, "a medium rule writes candidate: {:?}", v[0]);
        assert_eq!(v[0].score as u32, measured::points("H3008", Os::Windows));
        assert!(v[0].hunt_why().starts_with("rule H3008 (medium): "), "{}", v[0].hunt_why());
        assert_eq!(r.rule_medium, 1);
        // a low rule alone on a row no test judged (one host, no baseline): candidate, its measured points
        let events = vec![ev("H", "windows:persistence:registry_run_key", "C:\\updater.exe", "2026-10-28 12:00:00.000")];
        let (v, r) = evaluate(&events, &HuntSettings::default());
        assert_eq!(v[0].hunt, Hunt::Candidate, "{:?}", v[0]);
        assert_eq!(v[0].score as u32, measured::points("H3015", Os::Windows));
        assert!(v[0].hunt_why().starts_with("rule H3015 (low): Image in the drive root [T1036]"), "{}", v[0].hunt_why());
        assert_eq!(r.rule_high + r.rule_medium, 0, "a low rule is neither");
        // a rule measured common on the system would be noise (no state, no points, its clause);
        // none is on either reference today, so a high rule that fires counts with its measured points
        let events = vec![ev("H", "windows:persistence:registry_run_key", "C:\\Users\\bob\\x.txt:evil.exe", "2026-10-28 12:00:00.000")];
        let (v, _) = evaluate(&events, &HuntSettings::default());
        assert!(v[0].reasons.iter().any(|x| x.starts_with("rule H1011 ")), "{:?}", v[0]);
        assert_eq!(v[0].hunt, Hunt::Significant, "{:?}", v[0]);
        assert!(measured::counts("H1011", Os::Windows));
        assert!(v[0].score as u32 >= measured::points("H1011", Os::Windows), "{:?}", v[0]);
        // a medium rule on a stock entry: stock vouches for it, habitual, 0
        let events = vec![ev("H", "windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe", "2026-10-28 12:00:00.000")];
        let (v, _) = evaluate(&events, &HuntSettings::default());
        assert_eq!(v[0].hunt, Hunt::Habitual);
        assert_eq!(v[0].score, 0);
        // never the old words
        for v in evaluate(&events, &HuntSettings::default()).0 {
            assert!(!matches!(v.hunt.label(), "malicious" | "suspicious"));
        }
    }

    #[test]
    fn significant_from_statistics_alone() {
        diag::clear();
        let mut events = Vec::new();
        for h in 0..40 {
            for s in 0..30 {
                events.push(ev(&format!("H{h:02}"), "windows:persistence:windows_service", &format!("\"C:\\Program Files\\Vendor{s}\\svc.exe\""), &format!("2026-01-{:02} 10:{:02}:00.000", 1 + s % 20, s)));
            }
        }
        events.push(ev("H07", "windows:persistence:windows_service", "\"C:\\Program Files\\Updater\\a1b2c3d4e5f6.exe\"", "2026-10-05 03:12:00.000"));
        let (v, r) = evaluate(&events, &HuntSettings::default());
        let last = v.last().unwrap();
        // one low rule (random name) is not enough for suspicious; the statistics make it significant
        assert_eq!(last.hunt, Hunt::Significant, "{:?}", last);
        let low = measured::points("H3013", Os::Windows) as f64;
        assert!(last.score as f64 >= low + 13.0, "one low rule ({low}) and q <= alpha (13 or more): {:?}", last);
        assert_eq!(last.score as f64, (rarity_points(last.q.unwrap()) + low).round(), "{:?}", last);
        assert!(last.q.is_some_and(|q| q <= 0.05), "{:?}", last);
        assert!(last.reasons[0].starts_with("rule H3013 (low): "), "the rule's clause first: {:?}", last.reasons);
        assert!(last.reasons[1].starts_with("rare among "), "then the test's, in words: {:?}", last.reasons);
        assert!(last.reasons.iter().any(|x| x.contains("on 1 of 40 hosts")), "{:?}", last.reasons);
        assert_eq!(r.significant, 1);
        // the rest are on every host: habitual, p = 1
        assert!(v[..v.len() - 1].iter().all(|x| x.hunt == Hunt::Habitual && x.score == 0), "{:?}", v[0]);
        assert!(v[0].reasons.iter().any(|x| x == "on 40 of 40 hosts"), "{:?}", v[0]);
        assert_eq!(r.habitual, v.len() - 1);
    }

    #[test]
    fn known_good_csv_makes_the_row_habitual() {
        diag::clear();
        let dir = std::env::temp_dir().join(format!("faramir_hunt_kg_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("clean.csv");
        std::fs::write(
            &p,
            "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"pid\",\"subject_username\",\"target_username\",\"processname\",\"commandline\",\"parentprocessname\"\n\
             \"\",\"CLEAN\",\"windows:persistence:registry_run_key\",0,0,\"\",\"\",\"\",\"C:\\Program Files\\Vendor\\tool.exe /tray\",\"\"\n",
        )
        .unwrap();
        let b = parse_baseline("2026-10-01").unwrap();
        let events = vec![ev("H", "windows:persistence:registry_run_key", "C:\\Program Files\\Vendor\\tool.exe /tray", "2026-10-28 12:00:00.000")];
        let (v, r) = evaluate(&events, &HuntSettings { baseline: Some(b), known_good: vec![p], ..Default::default() });
        assert_eq!(v[0].hunt, Hunt::Habitual, "{:?}", v[0]);
        assert_eq!(r.known_good, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
