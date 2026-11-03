//! The timeline CSV: masstin's 19 columns, so a persistence timeline, a
//! lateral-movement timeline and a process timeline read with one schema.
//!
//! The 14 event columns are masstin's, in masstin's order. faramir fills
//! the ones that mean the same thing (`time_created`, `dst_computer`,
//! `event_type`, `event_id`, `target_user_name`, `subject_user_name`,
//! `detail`, `log_filename`) and leaves the logon-only ones empty
//! (`logon_type`, the two domains, `src_computer`, `src_ip`, `logon_id`).
//! Then the analysis tail: `hunt`, `hunt_score`, `hunt_why` written by the
//! hunt; `verdict`, `notes` written by the analyst and carried across runs
//! with `--carry-marks`.
//!
//! Quoting follows masstin's writer: an empty event field is `""`, a value
//! with a comma, a quote or a line break is quoted with inner quotes
//! doubled, anything else is bare; the tail is bare when empty (`,,,,,`).

use crate::event::Event;
use crate::hunt::{Marks, Verdict};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// The 14 event columns, in order: masstin's.
pub const BASE_COLUMNS: [&str; 14] = [
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

/// The analysis tail: three columns the hunt fills, two the analyst fills.
pub const TAIL_COLUMNS: [&str; 5] = ["hunt", "hunt_score", "hunt_why", "verdict", "notes"];

/// Number of columns every row has.
pub const COLUMNS: usize = 19;

/// The header, byte for byte masstin's.
pub const HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename,hunt,hunt_score,hunt_why,verdict,notes";

/// Empty tail, as written after a row nothing was said about.
pub const EMPTY_TAIL: &str = ",,,,,";

/// The 14 event columns of an event, as the CSV writes them (unescaped).
/// This is the row's identity for `--carry-marks`.
pub fn base_fields(e: &Event) -> [String; 14] {
    [
        e.timestamp.clone(),
        e.computer.clone(),
        e.artifact.clone(),
        e.event_id.to_string(),
        String::new(),
        e.target_username.clone(),
        String::new(),
        String::new(),
        String::new(),
        e.subject_username.clone(),
        String::new(),
        String::new(),
        e.commandline.clone().unwrap_or_else(|| "N/A".to_string()),
        e.parentprocessname.clone(),
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
            parentprocessname: "RunKey".to_string(),
        }
    }

    #[test]
    fn header_is_masstins_nineteen_columns() {
        let cols: Vec<&str> = HEADER.split(',').collect();
        assert_eq!(cols.len(), COLUMNS);
        assert_eq!(&cols[..14], &BASE_COLUMNS);
        assert_eq!(&cols[14..], &TAIL_COLUMNS);
        assert_eq!(EMPTY_TAIL.matches(',').count(), TAIL_COLUMNS.len());
        assert_eq!(HEADER, "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename,hunt,hunt_score,hunt_why,verdict,notes");
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
    fn base_fields_land_in_masstins_slots() {
        let b = base_fields(&event());
        assert_eq!(b[0], "2026-10-13 10:00:00.000");
        assert_eq!(b[1], "WIN-SRV01");
        assert_eq!(b[2], "windows:persistence:registry_run_key");
        assert_eq!(b[3], "0");
        assert_eq!(b[5], "User", "target_user_name");
        assert_eq!(b[9], "User", "subject_user_name");
        assert_eq!(b[12], "C:\\Users\\Admin\\malware.exe -d", "detail");
        assert_eq!(b[13], "RunKey", "log_filename");
        for k in [4, 6, 7, 8, 10, 11] {
            assert_eq!(b[k], "", "{} is a logon-only column", BASE_COLUMNS[k]);
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
            "2026-10-13 10:00:00.000,WIN-SRV01,windows:persistence:registry_run_key,0,\"\",User,\"\",\"\",\"\",User,\"\",\"\",C:\\Users\\Admin\\malware.exe -d,RunKey,significant,85,rule H1001 (high): x; deleted,,"
        );
        let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(content.as_bytes());
        let rec = rdr.records().next().unwrap().unwrap();
        assert_eq!(rec.len(), COLUMNS);
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
            artifact: "linux:cron:system_job".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "root".to_string(),
            target_username: "root".to_string(),
            processname: "x".to_string(),
            commandline: None,
            parentprocessname: "crond".to_string(),
        }];
        export_timeline(&events, &[], &Marks::default(), &test_csv, true).expect("export");
        let content = std::fs::read_to_string(&test_csv).unwrap();
        let _ = std::fs::remove_file(&test_csv);
        let line = content.lines().nth(1).unwrap();
        assert_eq!(line, "\"\",H,linux:cron:system_job,0,\"\",root,\"\",\"\",\"\",root,\"\",\"\",N/A,crond,,,,,");
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
        assert!(lines[1].ends_with(",RunKey,significant,90,rule H1001 (high): x,confirmed,\"#ir-4711, see ticket\""), "{}", lines[1]);
        assert!(lines[2].ends_with(",RunKey,,,,,"), "{}", lines[2]);
    }
}
