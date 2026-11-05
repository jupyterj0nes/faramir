//! The analyst's marks of an earlier faramir CSV (`verdict`, `notes`),
//! carried onto the rows of a new run over the same evidence
//! (`--carry-marks old.csv`). A row is found again by a hash of its 14
//! event columns, the same hash masstin's `--carry-marks` uses: the hunt's
//! columns are not part of the identity, so marking a row or running the
//! hunt again does not lose the mark.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::errors::FaramirError;

/// The 14 event columns, in order, as the header names them.
pub use crate::csv_out::BASE_COLUMNS;

/// Identity of a row across runs: FNV-1a over its 14 event columns (the
/// same function, over the same columns, as masstin's `row_hash`).
pub fn row_hash<S: AsRef<str>>(base: &[S]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for f in base.iter().take(BASE_COLUMNS.len()) {
        for &b in f.as_ref().as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Marked rows of one or more earlier timelines, by row hash.
#[derive(Debug, Default)]
pub struct Marks {
    map: HashMap<u64, (String, String)>,
    /// Files read without error.
    pub files: usize,
}

impl Marks {
    /// Read the marked rows of every path. A file that cannot be opened
    /// (7012) or is not a faramir timeline with a `verdict`/`notes` tail
    /// (7014) is reported and skipped; the rest are loaded (7013).
    pub fn load(paths: &[PathBuf]) -> (Marks, Vec<FaramirError>) {
        let mut marks = Marks::default();
        let mut errors = Vec::new();
        for path in paths {
            let shown = path.display().to_string();
            let mut rdr = match csv::ReaderBuilder::new().has_headers(false).flexible(true).from_path(path) {
                Ok(r) => r,
                Err(e) => {
                    errors.push(FaramirError::HuntMarksOpenFailed(format!("{shown}: {e}")));
                    continue;
                }
            };
            let mut records = rdr.records();
            let header: Vec<String> = match records.next() {
                Some(Ok(h)) => h.iter().map(|c| c.trim().trim_start_matches('\u{feff}').trim_matches('"').to_ascii_lowercase()).collect(),
                _ => {
                    errors.push(FaramirError::HuntMarksNotTimeline(format!("{shown}: cannot read the header")));
                    continue;
                }
            };
            if header.len() < BASE_COLUMNS.len() || header.iter().take(BASE_COLUMNS.len()).zip(BASE_COLUMNS).any(|(a, b)| a != b) {
                errors.push(FaramirError::HuntMarksNotTimeline(format!("{shown}: the header does not start with the 14 event columns (timestamp … source_file)")));
                continue;
            }
            let (vi, ni) = match (header.iter().position(|c| c == "verdict"), header.iter().position(|c| c == "notes")) {
                (Some(v), Some(n)) => (v, n),
                _ => {
                    errors.push(FaramirError::HuntMarksNotTimeline(format!("{shown}: no verdict/notes columns (written before the analysis tail existed)")));
                    continue;
                }
            };
            let mut loaded = 0usize;
            for rec in records.flatten() {
                let v = rec.get(vi).unwrap_or("");
                let n = rec.get(ni).unwrap_or("");
                if v.is_empty() && n.is_empty() {
                    continue;
                }
                let base: Vec<&str> = rec.iter().take(BASE_COLUMNS.len()).collect();
                if base.len() < BASE_COLUMNS.len() {
                    continue;
                }
                marks.map.insert(row_hash(&base), (v.to_string(), n.to_string()));
                loaded += 1;
            }
            marks.files += 1;
            errors.push(FaramirError::HuntMarksLoaded(format!("{loaded} marked row(s) from {shown}")));
        }
        (marks, errors)
    }

    /// The marks of the row with these 14 event columns.
    pub fn get<S: AsRef<str>>(&self, base: &[S]) -> Option<&(String, String)> {
        self.map.get(&row_hash(base))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("faramir_marks_{}_{}", std::process::id(), name))
    }

    #[test]
    fn hash_depends_on_the_fourteen_columns_only() {
        let a = ["t", "h", "a", "0", "", "u", "", "", "", "u", "", "", "c", "pp"];
        let mut b = a.to_vec();
        b.extend(["significant", "90", "why", "confirmed", "note"]);
        assert_eq!(row_hash(&a), row_hash(&b));
        let mut c = a;
        c[12] = "other";
        assert_ne!(row_hash(&a), row_hash(&c));
        assert_ne!(row_hash(&["a", "b"]), row_hash(&["ab", ""]), "field boundaries count");
        // masstin's value for the same fields (FNV-1a 64, 0xff between fields)
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for f in a {
            for &x in f.as_bytes() {
                h ^= x as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            h ^= 0xff;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        assert_eq!(row_hash(&a), h);
    }

    #[test]
    fn loads_marked_rows_and_skips_the_rest() {
        let p = tmp("ok.csv");
        std::fs::write(
            &p,
            "timestamp,computer,artifact,event_id,state,target_username,reserved_1,processname,reserved_2,subject_username,reserved_3,pid,commandline,source_file,hunt,hunt_score,hunt_why,verdict,notes\n\
             2026-10-28 12:00:00.000,H,linux:cron:system_job,0,\"\",root,\"\",\"\",\"\",root,\"\",\"\",/tmp/.x/run.sh,crond,significant,90,rule H3001 (high): x,confirmed,#ir-4711\n\
             2026-10-28 12:00:00.000,H,linux:cron:system_job,0,\"\",root,\"\",\"\",\"\",root,\"\",\"\",/usr/bin/x,crond,,,,,\n\
             2026-10-28 12:00:00.000,H,linux:cron:system_job,0,\"\",root,\"\",\"\",\"\",root,\"\",\"\",/usr/bin/y,crond,habitual,0,stock Linux entry,,seen before\n",
        )
        .unwrap();
        let (m, errs) = Marks::load(std::slice::from_ref(&p));
        let _ = std::fs::remove_file(&p);
        assert_eq!(m.len(), 2);
        assert_eq!(m.files, 1);
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].error_number(), 7013);
        let base = ["2026-10-28 12:00:00.000", "H", "linux:cron:system_job", "0", "", "root", "", "", "", "root", "", "", "/tmp/.x/run.sh", "crond"];
        assert_eq!(m.get(&base), Some(&("confirmed".to_string(), "#ir-4711".to_string())));
        let base = ["2026-10-28 12:00:00.000", "H", "linux:cron:system_job", "0", "", "root", "", "", "", "root", "", "", "/usr/bin/y", "crond"];
        assert_eq!(m.get(&base), Some(&(String::new(), "seen before".to_string())));
        let base = ["2026-10-28 12:00:00.000", "H", "linux:cron:system_job", "0", "", "root", "", "", "", "root", "", "", "/usr/bin/x", "crond"];
        assert_eq!(m.get(&base), None);
    }

    #[test]
    fn missing_file_and_foreign_csv_are_reported() {
        let (m, errs) = Marks::load(&[tmp("missing.csv")]);
        assert!(m.is_empty());
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].error_number(), 7012);

        let p = tmp("foreign.csv");
        std::fs::write(&p, "timestamp,computer,artifact,event_id,pid\n1,2,3,4,5\n").unwrap();
        let (m, errs) = Marks::load(std::slice::from_ref(&p));
        let _ = std::fs::remove_file(&p);
        assert!(m.is_empty());
        assert_eq!(errs[0].error_number(), 7014);

        let p = tmp("old.csv");
        std::fs::write(&p, "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename\n").unwrap();
        let (m, errs) = Marks::load(std::slice::from_ref(&p));
        let _ = std::fs::remove_file(&p);
        assert!(m.is_empty());
        assert_eq!(errs[0].error_number(), 7014);
        assert!(errs[0].to_string().contains("verdict/notes"), "{}", errs[0]);
    }
}
