//! The timeline CSV: 19 columns, as wide as masstin's timeline and with
//! every faramir field in the same vertical as the masstin field that means
//! the same thing, under faramir's own names. A persistence timeline, a
//! lateral-movement timeline and a process timeline then line up column by
//! column, and a case tool maps each tool's header once.
//!
//! The 14 event columns (masstin's name in the third column):
//!
//! | # | faramir | masstin | content |
//! |---|---|---|---|
//! | 1 | `timestamp` | time_created | key last-write time, unit mtime; empty when unknown |
//! | 2 | `computer` | dst_computer | host name |
//! | 3 | `artifact` | event_type | the technique |
//! | 4 | `event_id` | event_id | `0` |
//! | 5 | `state` | logon_type | `live`, `deleted`, `removed_since_vss`, `carved`, `carved_deleted`, `previous_version` |
//! | 6 | `target_username` | target_user_name | the account the entry runs as |
//! | 7 | `reserved_1` | target_domain_name | empty |
//! | 8 | `processname` | src_computer | image name |
//! | 9 | `reserved_2` | src_ip | empty |
//! | 10 | `subject_username` | subject_user_name | the same account |
//! | 11 | `reserved_3` | subject_domain_name | empty |
//! | 12 | `pid` | logon_id | process id when known (running processes), `0` otherwise |
//! | 13 | `commandline` | detail | what runs |
//! | 14 | `source_file` | log_filename | the file the entry was read from, and the key inside it |
//!
//! Then the analysis tail shared by masstin, caarea, faramir and allymacb:
//! `hunt`, `hunt_score`, `hunt_why` written by the hunt; `verdict`, `notes`
//! written by the analyst and carried across runs with `--carry-marks`.
//!
//! Quoting follows masstin's writer: an empty event field is `""`, a value
//! with a comma, a quote or a line break is quoted with inner quotes
//! doubled, anything else is bare; the tail is bare when empty (`,,,,,`).

use crate::event::Event;
use crate::hunt::{Marks, Verdict};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// The 14 event columns, in order: faramir's names in masstin's verticals.
pub const BASE_COLUMNS: [&str; 14] = [
    "timestamp",
    "computer",
    "artifact",
    "event_id",
    "state",
    "target_username",
    "reserved_1",
    "processname",
    "reserved_2",
    "subject_username",
    "reserved_3",
    "pid",
    "commandline",
    "source_file",
];

/// The analysis tail: three columns the hunt fills, two the analyst fills.
pub const TAIL_COLUMNS: [&str; 5] = ["hunt", "hunt_score", "hunt_why", "verdict", "notes"];

/// Number of columns every row has.
pub const COLUMNS: usize = 19;

/// The header, as written (bare).
pub const HEADER: &str = "timestamp,computer,artifact,event_id,state,target_username,reserved_1,processname,reserved_2,subject_username,reserved_3,pid,commandline,source_file,hunt,hunt_score,hunt_why,verdict,notes";

/// Empty tail, as written after a row nothing was said about.
pub const EMPTY_TAIL: &str = ",,,,,";

/// The `state` column: how the entry was obtained, read off the artifact
/// name. `live` is what the system shows now; the rest are no longer on the
/// live system.
pub fn state_of(artifact: &str) -> &'static str {
    let rest = artifact.strip_prefix("windows:persistence:").or_else(|| artifact.strip_prefix("linux:")).unwrap_or(artifact);
    if rest.starts_with("carved:deleted:") {
        "carved_deleted"
    } else if rest.starts_with("carved:") {
        "carved"
    } else if rest.starts_with("removed_since_vss:") {
        "removed_since_vss"
    } else if rest.starts_with("deleted:") {
        "deleted"
    } else if rest.starts_with("previous_version:") {
        "previous_version"
    } else {
        "live"
    }
}

/// The 14 event columns of an event, as the CSV writes them (unescaped).
/// This is the row's identity for `--carry-marks`.
pub fn base_fields(e: &Event) -> [String; 14] {
    [
        e.timestamp.clone(),
        e.computer.clone(),
        e.artifact.clone(),
        e.event_id.to_string(),
        state_of(&e.artifact).to_string(),
        e.target_username.clone(),
        String::new(),
        e.processname.clone(),
        String::new(),
        e.subject_username.clone(),
        String::new(),
        e.pid.to_string(),
        e.commandline.clone().unwrap_or_else(|| "N/A".to_string()),
        e.source_file.clone(),
    ]
}

/// Quote one event field the way masstin's writer does.
pub fn q(s: &str) -> String {
    if s.is_empty() {
        "\"\"".to_string()
    } else if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Quote one tail field: like [`q`], but an empty value is written bare.
pub fn qt(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        q(s)
    }
}

/// The tail of a row from its five values; `,,,,,` when all are empty.
pub fn tail(hunt: &str, hunt_score: &str, hunt_why: &str, verdict: &str, notes: &str) -> String {
    if hunt.is_empty() && hunt_score.is_empty() && hunt_why.is_empty() && verdict.is_empty() && notes.is_empty() {
        return EMPTY_TAIL.to_string();
    }
    format!(",{},{},{},{},{}", qt(hunt), qt(hunt_score), qt(hunt_why), qt(verdict), qt(notes))
}

/// Exports the timeline to a CSV file. `verdicts` lines up with `events`;
/// when it is shorter (hunting off) `hunt`, `hunt_score` and `hunt_why` are
/// written empty. `marks` gives `verdict` and `notes` for the rows an
/// earlier CSV marked.
pub fn export_timeline(events: &[Event], verdicts: &[Verdict], marks: &Marks, output_file: &Path, silent: bool) -> std::io::Result<()> {
    if let Some(parent) = output_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "{HEADER}")?;

    let empty = Verdict::default();
    let no_marks = (String::new(), String::new());
    let mut line = String::with_capacity(512);
    for (i, event) in events.iter().enumerate() {
        let base = base_fields(event);
        let v = verdicts.get(i).unwrap_or(&empty);
        let (verdict, notes) = if marks.is_empty() { &no_marks } else { marks.get(&base).unwrap_or(&no_marks) };
        let (hunt, hunt_score, hunt_why) = if verdicts.get(i).is_some() { (v.hunt.label(), v.hunt_score(), v.hunt_why()) } else { ("", String::new(), String::new()) };
        line.clear();
        for (k, f) in base.iter().enumerate() {
            if k > 0 {
                line.push(',');
            }
            line.push_str(&q(f));
        }
        line.push_str(&tail(hunt, &hunt_score, &hunt_why, verdict, notes));
        line.push('\n');
        writer.write_all(line.as_bytes())?;
    }

    if !silent {
        println!("✅ Timeline successfully saved to: {}", output_file.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hunt::Hunt;
    use std::io::Read;

    fn event() -> Event {
        Event {
            timestamp: "2026-10-13 10:00:00.000".to_string(),
            computer: "WIN-SRV01".to_string(),
            artifact: "windows:persistence:registry_run_key".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "User".to_string(),
            target_username: "User".to_string(),
            processname: "malware.exe".to_string(),
            commandline: Some("C:\\Users\\Admin\\malware.exe -d".to_string()),
            source_file: "C:\\Windows\\System32\\config\\SOFTWARE:Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
        }
    }

    /// masstin's 14 event columns, the verticals faramir's line up with.
    const MASSTIN_COLUMNS: [&str; 14] = [
        "time_created",
        "dst_computer",
        "event_type",
        "event_id",
        "logon_type",
        "target_user_name",
        "target_domain_name",
        "src_computer",
        "src_ip",
        "subject_user_name",
        "subject_domain_name",
        "logon_id",
        "detail",
        "log_filename",
    ];

    #[test]
    fn header_is_as_wide_as_masstins_with_faramirs_names() {
        let cols: Vec<&str> = HEADER.split(',').collect();
        assert_eq!(cols.len(), COLUMNS);
        assert_eq!(cols.len(), MASSTIN_COLUMNS.len() + TAIL_COLUMNS.len());
        assert_eq!(&cols[..14], &BASE_COLUMNS);
        assert_eq!(&cols[14..], &TAIL_COLUMNS);
        assert_eq!(EMPTY_TAIL.matches(',').count(), TAIL_COLUMNS.len());
        assert_eq!(HEADER, "timestamp,computer,artifact,event_id,state,target_username,reserved_1,processname,reserved_2,subject_username,reserved_3,pid,commandline,source_file,hunt,hunt_score,hunt_why,verdict,notes");
        // the same verticals as masstin, never masstin's names (except the one both tools spell alike)
        for (f, m) in BASE_COLUMNS.iter().zip(MASSTIN_COLUMNS) {
            assert!(f == &m || !MASSTIN_COLUMNS.contains(f), "{f} is a masstin name in another vertical");
        }
        assert_eq!(BASE_COLUMNS[3], MASSTIN_COLUMNS[3], "event_id is the one name both share");
        // the tail is the one shared by the four tools
        assert_eq!(TAIL_COLUMNS, ["hunt", "hunt_score", "hunt_why", "verdict", "notes"]);
        // no column is named twice
        let mut names: Vec<&str> = cols.clone();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), COLUMNS);
    }

    #[test]
    fn quoting_matches_masstins_writer() {
        assert_eq!(q(""), "\"\"");
        assert_eq!(q("plain"), "plain");
        assert_eq!(q("a,b"), "\"a,b\"");
        assert_eq!(q("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(q("two\nlines"), "\"two\nlines\"");
        assert_eq!(qt(""), "");
        assert_eq!(qt("x"), "x");
    }

    #[test]
    fn tail_is_bare_when_empty_and_quoted_when_needed() {
        assert_eq!(tail("", "", "", "", ""), ",,,,,");
        assert_eq!(tail("habitual", "0", "stock Linux entry", "", ""), ",habitual,0,stock Linux entry,,");
        assert_eq!(tail("", "", "", "benign", "say \"hi\", twice"), ",,,,benign,\"say \"\"hi\"\", twice\"");
    }

    #[test]
    fn state_is_read_off_the_artifact() {
        assert_eq!(state_of("windows:persistence:registry_run_key"), "live");
        assert_eq!(state_of("windows:persistence:deleted:registry_run_key"), "deleted");
        assert_eq!(state_of("windows:persistence:removed_since_vss:windows_service"), "removed_since_vss");
        assert_eq!(state_of("windows:persistence:carved:registry_run_key"), "carved");
        assert_eq!(state_of("windows:persistence:carved:deleted:registry_run_key"), "carved_deleted");
        assert_eq!(state_of("linux:cron:system_job"), "live");
        assert_eq!(state_of("linux:deleted:cron:system_job"), "deleted");
        assert_eq!(state_of("linux:previous_version:sudoers:nopasswd"), "previous_version");
        assert_eq!(state_of("linux:deleted:file"), "deleted");
    }

    #[test]
    fn base_fields_fill_faramirs_slots_and_leave_the_reserved_ones_empty() {
        let mut e = event();
        e.pid = 4242;
        let b = base_fields(&e);
        assert_eq!(b[0], "2026-10-13 10:00:00.000", "timestamp");
        assert_eq!(b[1], "WIN-SRV01", "computer");
        assert_eq!(b[2], "windows:persistence:registry_run_key", "artifact");
        assert_eq!(b[3], "0", "event_id");
        assert_eq!(b[4], "live", "state");
        assert_eq!(b[5], "User", "target_username");
        assert_eq!(b[7], "malware.exe", "processname");
        assert_eq!(b[9], "User", "subject_username");
        assert_eq!(b[11], "4242", "pid");
        assert_eq!(b[12], "C:\\Users\\Admin\\malware.exe -d", "commandline");
        assert_eq!(b[13], "C:\\Windows\\System32\\config\\SOFTWARE:Microsoft\\Windows\\CurrentVersion\\Run", "source_file");
        for k in [6, 8, 10] {
            assert_eq!(b[k], "", "{} is reserved", BASE_COLUMNS[k]);
            assert!(BASE_COLUMNS[k].starts_with("reserved_"));
        }
        // every field of the event reaches the CSV: nothing is dropped
        let joined = b.join("\x1f");
        for v in [e.timestamp.as_str(), e.computer.as_str(), e.artifact.as_str(), e.target_username.as_str(), e.processname.as_str(), e.subject_username.as_str(), "4242", e.commandline.as_deref().unwrap(), e.source_file.as_str()] {
            assert!(joined.contains(v), "{v} missing from the event columns");
        }
    }

    #[test]
    fn test_export_timeline_format() {
        let temp_dir = std::env::temp_dir();
        let test_csv = temp_dir.join(format!("test_timeline_{}.csv", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));

        let verdicts = vec![Verdict { hunt: Hunt::Significant, score: 85, q: Some(0.0123), reasons: vec!["rule H1001 (high): x".into(), "deleted".into()] }];
        export_timeline(std::slice::from_ref(&event()), &verdicts, &Marks::default(), &test_csv, true).expect("Failed to export timeline");

        let mut content = String::new();
        let mut file = File::open(&test_csv).expect("Failed to open test csv");
        file.read_to_string(&mut content).expect("Failed to read test csv");
        let _ = std::fs::remove_file(&test_csv);

        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], HEADER);
        assert_eq!(
            lines[1],
            "2026-10-13 10:00:00.000,WIN-SRV01,windows:persistence:registry_run_key,0,live,User,\"\",malware.exe,\"\",User,\"\",0,C:\\Users\\Admin\\malware.exe -d,C:\\Windows\\System32\\config\\SOFTWARE:Microsoft\\Windows\\CurrentVersion\\Run,significant,85,rule H1001 (high): x; deleted,,"
        );
        let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(content.as_bytes());
        let rec = rdr.records().next().unwrap().unwrap();
        assert_eq!(rec.len(), COLUMNS);
        assert_eq!(rec.get(4), Some("live"));
        assert_eq!(rec.get(7), Some("malware.exe"));
        assert_eq!(rec.get(11), Some("0"));
        assert_eq!(rec.get(14), Some("significant"));
        assert_eq!(rec.get(15), Some("85"));
        assert_eq!(rec.get(16), Some("rule H1001 (high): x; deleted"));
    }

    #[test]
    fn test_export_without_verdicts_leaves_the_tail_empty() {
        let temp_dir = std::env::temp_dir();
        let test_csv = temp_dir.join(format!("test_timeline_nohunt_{}.csv", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let events = vec![Event {
            timestamp: String::new(),
            computer: "H".to_string(),
            artifact: "linux:deleted:cron:system_job".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "root".to_string(),
            target_username: "root".to_string(),
            processname: "x".to_string(),
            commandline: None,
            source_file: "/etc/cron.d/x".to_string(),
        }];
        export_timeline(&events, &[], &Marks::default(), &test_csv, true).expect("export");
        let content = std::fs::read_to_string(&test_csv).unwrap();
        let _ = std::fs::remove_file(&test_csv);
        let line = content.lines().nth(1).unwrap();
        assert_eq!(line, "\"\",H,linux:deleted:cron:system_job,0,deleted,root,\"\",x,\"\",root,\"\",0,N/A,/etc/cron.d/x,,,,,");
        let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(content.as_bytes());
        let rec = rdr.records().next().unwrap().unwrap();
        assert_eq!(rec.len(), COLUMNS);
        assert!(rec.iter().skip(14).all(|f| f.is_empty()));
    }

    #[test]
    fn marks_are_carried_onto_the_same_row() {
        let temp_dir = std::env::temp_dir();
        let first = temp_dir.join(format!("test_marks_a_{}.csv", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let e = event();
        let verdicts = vec![Verdict { hunt: Hunt::Candidate, score: 10, q: None, reasons: vec!["written after the baseline".into()] }];
        export_timeline(std::slice::from_ref(&e), &verdicts, &Marks::default(), &first, true).unwrap();
        // the analyst marks the row by hand
        let marked = std::fs::read_to_string(&first).unwrap().replace("written after the baseline,,", "written after the baseline,confirmed,\"#ir-4711, see ticket\"");
        std::fs::write(&first, marked).unwrap();
        let (marks, errs) = Marks::load(std::slice::from_ref(&first));
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert_eq!(marks.len(), 1);
        let second = temp_dir.join(format!("test_marks_b_{}.csv", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let mut other = e.clone();
        other.commandline = Some("C:\\other.exe".into());
        // the hunt may say something else next time; the mark follows the event columns
        let verdicts = vec![Verdict { hunt: Hunt::Significant, score: 90, q: None, reasons: vec!["rule H1001 (high): x".into()] }, Verdict::default()];
        export_timeline(&[e, other], &verdicts, &marks, &second, true).unwrap();
        let content = std::fs::read_to_string(&second).unwrap();
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);
        let lines: Vec<&str> = content.lines().collect();
        assert!(lines[1].ends_with("\\Run,significant,90,rule H1001 (high): x,confirmed,\"#ir-4711, see ticket\""), "{}", lines[1]);
        assert!(lines[2].ends_with("\\Run,,,,,"), "{}", lines[2]);
    }
}
