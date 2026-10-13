use faramir::parsers::linux::sudoers::*;
use std::fs::File;
use std::io::Write;

fn create_temp_sudoers(content: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("sudoers_{}_{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
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

#[test]
fn test_sudoers_nopasswd_all() {
    let (p, _g) = create_temp_sudoers("attacker ALL=(ALL:ALL) NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:sudoers:nopasswd");
    assert_eq!(evs[0].subject_username, "attacker");
}

#[test]
fn test_sudoers_nopasswd_specific_command() {
    let (p, _g) = create_temp_sudoers("backup ALL=(root) NOPASSWD: /usr/local/bin/backup\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].subject_username, "backup");
}

#[test]
fn test_sudoers_group_nopasswd() {
    let (p, _g) = create_temp_sudoers("%wheel ALL=(ALL) NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].subject_username, "%wheel");
}

#[test]
fn test_sudoers_not_authenticate() {
    let (p, _g) = create_temp_sudoers("user1 ALL=(ALL) !authenticate\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].subject_username, "user1");
}

#[test]
fn test_sudoers_defaults_env_keep() {
    let (p, _g) = create_temp_sudoers("Defaults env_keep += \"LD_PRELOAD LD_LIBRARY_PATH\"\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:sudoers:defaults_override");
}

#[test]
fn test_sudoers_defaults_not_lecture() {
    let (p, _g) = create_temp_sudoers("Defaults !lecture\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_sudoers_benign_rules_ignored() {
    let (p, _g) = create_temp_sudoers("root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_sudoers_comments_ignored() {
    let (p, _g) = create_temp_sudoers("# user ALL=(ALL) NOPASSWD: ALL\n# another comment\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_sudoers_empty_file_err() {
    let (p, _g) = create_temp_sudoers("");
    let err = parse_sudoers_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_sudoers_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/sudoers_123");
    let err = parse_sudoers_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_sudoers_multiple_nopasswd() {
    let (p, _g) = create_temp_sudoers("user1 ALL=NOPASSWD: ALL\nuser2 ALL=NOPASSWD: /bin/sh\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_sudoers_parent_is_sudo() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "sudo");
}

#[test]
fn test_sudoers_processname_is_sudo() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "sudo");
}

#[test]
fn test_sudoers_target_user_is_root() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_sudoers_line_number_in_commandline() {
    let (p, _g) = create_temp_sudoers("# 1\n# 2\nu ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("line 3"));
}

#[test]
fn test_sudoers_filename_in_commandline() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let fname = p.file_name().unwrap().to_str().unwrap();
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains(fname));
}

#[test]
fn test_sudoers_whitespaces_around_directive() {
    let (p, _g) = create_temp_sudoers("   u    ALL=(ALL)    NOPASSWD:    /bin/ls   \n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_sudoers_percent_admin_group() {
    let (p, _g) = create_temp_sudoers("%admin ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "%admin");
}

#[test]
fn test_sudoers_env_keep_spaces() {
    let (p, _g) = create_temp_sudoers("Defaults   env_keep   +=   \"HOME\"  \n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_sudoers_defaults_user_specific() {
    let (p, _g) = create_temp_sudoers("Defaults:user1 !authenticate\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_sudoers_defaults_target_user_is_root() {
    let (p, _g) = create_temp_sudoers("Defaults env_keep += \"FOO\"\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_sudoers_both_nopasswd_and_defaults() {
    let (p, _g) = create_temp_sudoers("Defaults env_keep += \"X\"\nuser ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_sudoers_computer_name() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "SRV-LNX-01").unwrap();
    assert_eq!(evs[0].computer, "SRV-LNX-01");
}

#[test]
fn test_sudoers_event_id_zero() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_sudoers_pid_zero() {
    let (p, _g) = create_temp_sudoers("u ALL=NOPASSWD: ALL\n");
    let evs = parse_sudoers_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}
