mod common;
use faramir::parsers::linux::cron::*;
use std::fs::File;
use std::io::Write;

fn create_temp_cron(content: &str, prefix: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("{}_{}_{}.cron", prefix, std::process::id(), common::unique_suffix()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }
    let guard = tempfile_guard::FileGuard(path.clone());
    (path, guard)
}

mod tempfile_guard {
    pub struct FileGuard(pub std::path::PathBuf);
    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

// ─── System Cron Tests ────────────────────────────────────────────────────────

#[test]
fn test_cron_system_valid_simple() {
    let (p, _g) = create_temp_cron("0 * * * * root /usr/local/bin/backup.sh\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "/usr/local/bin/backup.sh");
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_cron_system_multiple_entries() {
    let (p, _g) = create_temp_cron("0 1 * * * root /bin/job1\n*/5 * * * * www-data /bin/job2\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].subject_username, "root");
    assert_eq!(evs[1].subject_username, "www-data");
}

#[test]
fn test_cron_system_with_args() {
    let (p, _g) = create_temp_cron("10 2 * * * root /usr/bin/python3 /opt/run.py --daemon --quiet\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].commandline.as_ref().unwrap().contains("--daemon --quiet"));
}

#[test]
fn test_cron_system_ignores_comments() {
    let (p, _g) = create_temp_cron("# Comment line\n# Another comment\n0 0 * * * root /bin/run\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_system_ignores_env_vars() {
    let (p, _g) = create_temp_cron("SHELL=/bin/bash\nPATH=/usr/bin\nMAILTO=root\nHOME=/\n0 0 * * * root /bin/run\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_system_empty_file_err() {
    let (p, _g) = create_temp_cron("", "sys_cron_empty");
    let err = parse_cron_system_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
    assert_eq!(err.error_number(), 1004);
}

#[test]
fn test_cron_system_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/path/cron_abc123");
    let err = parse_cron_system_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
    assert_eq!(err.error_number(), 1001);
}

/// A malformed line is reported as `ERR_LNX_CRON_SYNTAX` and skipped; the
/// file is not abandoned (one bad line used to hide every other job).
#[test]
fn test_cron_system_malformed_lines_are_reported_and_skipped() {
    for bad in ["0", "0 1", "0 1 2", "0 1 2 3", "0 1 2 3 4", "0 1 2 3 4 root", "@reboot", "@reboot root"] {
        let (p, _g) = create_temp_cron(&format!("{bad}\n0 2 * * * root /opt/good.sh\n"), "sys_cron_bad");
        faramir::windows::diag::clear();
        let evs = parse_cron_system_file(&p, "HOST").unwrap();
        assert_eq!(evs.len(), 1, "{bad:?}: the good line survives");
        assert!(evs[0].commandline.as_deref().unwrap().contains("/opt/good.sh"));
        assert_eq!(faramir::windows::diag::count("ERR_LNX_CRON_SYNTAX"), 1, "{bad:?}");
        let text = faramir::windows::diag::snapshot()[0].to_string();
        assert!(text.contains("line 1") || text.contains(":1:"), "{text}");
    }
}

#[test]
fn test_cron_system_reboot_and_special_schedules() {
    let (p, _g) = create_temp_cron("@reboot root /opt/lab/boot.sh --now\n@daily bob /home/bob/daily.sh\n@hourly  root  /usr/bin/true\n", "sys_cron_special");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
    assert_eq!(evs[0].subject_username, "root");
    assert_eq!(evs[0].processname, "/opt/lab/boot.sh");
    assert!(evs[0].commandline.as_deref().unwrap().contains("@reboot /opt/lab/boot.sh --now"), "{:?}", evs[0].commandline);
    assert_eq!(evs[1].subject_username, "bob");
    assert!(evs[1].commandline.as_deref().unwrap().contains("@daily /home/bob/daily.sh"));
}

#[test]
fn test_cron_system_environment_lines_are_not_jobs() {
    let (p, _g) = create_temp_cron("SHELL=/bin/sh\nPATH=/usr/bin\nMAILTO=root\nLANG=C.UTF-8\nCRON_TZ=UTC\n0 2 * * * root /opt/good.sh\n", "sys_cron_env");
    faramir::windows::diag::clear();
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(faramir::windows::diag::count("ERR_LNX_CRON_SYNTAX"), 0);
    assert!(is_env_assignment("LANG=C.UTF-8"));
    assert!(is_env_assignment("MAILTO="));
    assert!(!is_env_assignment("0 2 * * * root echo a=b"));
    assert!(!is_env_assignment("=x"));
    assert!(!is_env_assignment("1ABC=x"));
}

#[test]
fn test_cron_system_user_nobody() {
    let (p, _g) = create_temp_cron("* * * * * nobody /tmp/miner\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "nobody");
}

#[test]
fn test_cron_system_step_values() {
    let (p, _g) = create_temp_cron("*/10 */2 1-5 * * root /bin/step\n", "sys_cron");
    let evs = parse_cron_system_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "/bin/step");
}

// ─── Spool Cron Tests ─────────────────────────────────────────────────────────

#[test]
fn test_cron_spool_valid_entry() {
    let (p, _g) = create_temp_cron("30 4 * * * /usr/bin/daily_user.sh\n", "alice");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "/usr/bin/daily_user.sh");
}

#[test]
fn test_cron_spool_empty_file_err() {
    let (p, _g) = create_temp_cron("", "bob");
    let err = parse_cron_spool_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_cron_spool_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/spool_file_123");
    let err = parse_cron_spool_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_cron_spool_syntax_error() {
    let (p, _g) = create_temp_cron("1 2 3 4\n", "carol");
    let err = parse_cron_spool_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_CRON_SYNTAX");
}

#[test]
fn test_cron_spool_special_reboot() {
    let (p, _g) = create_temp_cron("@reboot /tmp/backdoor.sh\n", "dave");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].commandline.as_ref().unwrap().contains("@reboot"));
}

#[test]
fn test_cron_spool_special_daily() {
    let (p, _g) = create_temp_cron("@daily /opt/daily.sh\n", "eve");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_special_hourly() {
    let (p, _g) = create_temp_cron("@hourly /opt/hourly.sh\n", "frank");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_special_weekly() {
    let (p, _g) = create_temp_cron("@weekly /opt/weekly.sh\n", "grace");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_special_monthly() {
    let (p, _g) = create_temp_cron("@monthly /opt/monthly.sh\n", "heidi");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_special_yearly() {
    let (p, _g) = create_temp_cron("@yearly /opt/yearly.sh\n", "ivan");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_special_annually() {
    let (p, _g) = create_temp_cron("@annually /opt/annually.sh\n", "judy");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_special_missing_command_err() {
    let (p, _g) = create_temp_cron("@reboot\n", "mallory");
    let err = parse_cron_spool_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_CRON_NO_CMD");
    assert_eq!(err.error_number(), 2003);
}

#[test]
fn test_cron_spool_ignores_comments() {
    let (p, _g) = create_temp_cron("# comments\n0 0 * * * /bin/cmd\n", "oscar");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_spool_ignores_env() {
    let (p, _g) = create_temp_cron("MAILTO=admin\n0 0 * * * /bin/cmd\n", "peggy");
    let evs = parse_cron_spool_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

// ─── Anacrontab Tests ─────────────────────────────────────────────────────────

#[test]
fn test_anacron_valid_entry() {
    let (p, _g) = create_temp_cron("1 5 cron.daily run-parts --report /etc/cron.daily\n", "anacron");
    let evs = parse_anacrontab_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "run-parts");
    assert!(evs[0].commandline.as_ref().unwrap().contains("cron.daily"));
}

#[test]
fn test_anacron_multiple_jobs() {
    let (p, _g) = create_temp_cron("1 5 job1 /bin/cmd1\n7 10 job2 /bin/cmd2\n30 15 job3 /bin/cmd3\n", "anacron");
    let evs = parse_anacrontab_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn test_anacron_empty_file_err() {
    let (p, _g) = create_temp_cron("", "anacron_empty");
    let err = parse_anacrontab_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_anacron_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/anacrontab");
    let err = parse_anacrontab_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_anacron_syntax_error_too_few_fields() {
    let (p, _g) = create_temp_cron("1 5 job1\n", "anacron_bad");
    let err = parse_anacrontab_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_ANACRON_INVALID");
    assert_eq!(err.error_number(), 2004);
}

#[test]
fn test_anacron_ignores_comments_and_env() {
    let (p, _g) = create_temp_cron("# comments\nSHELL=/bin/sh\nSTART_HOURS_RANGE=3-22\n1 5 daily /bin/cmd\n", "anacron");
    let evs = parse_anacrontab_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

// ─── Periodic Cron Tests ──────────────────────────────────────────────────────

#[test]
fn test_cron_periodic_hourly() {
    let (p, _g) = create_temp_cron("#!/bin/sh\necho hourly", "cron.hourly");
    let evs = parse_cron_periodic_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_cron_periodic_daily() {
    let (p, _g) = create_temp_cron("#!/bin/sh\necho daily", "cron.daily");
    let evs = parse_cron_periodic_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_periodic_weekly() {
    let (p, _g) = create_temp_cron("#!/bin/sh\necho weekly", "cron.weekly");
    let evs = parse_cron_periodic_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_periodic_monthly() {
    let (p, _g) = create_temp_cron("#!/bin/sh\necho monthly", "cron.monthly");
    let evs = parse_cron_periodic_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_cron_periodic_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/script.sh");
    let err = parse_cron_periodic_script(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}
