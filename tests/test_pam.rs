use faramir::parsers::linux::pam::*;
use std::fs::File;
use std::io::Write;

fn create_temp_pam(content: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("pam_{}_{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
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
fn test_pam_exec_auth() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so seteuid /tmp/hook.sh\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:exec_backdoor");
    assert_eq!(evs[0].processname, "pam_exec.so");
}

#[test]
fn test_pam_exec_session() {
    let (p, _g) = create_temp_pam("session optional pam_exec.so quiet /usr/local/bin/logger\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:exec_backdoor");
}

#[test]
fn test_pam_permit_auth_bypass() {
    let (p, _g) = create_temp_pam("auth sufficient pam_permit.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:permit_bypass");
}

#[test]
fn test_pam_permit_account_bypass() {
    let (p, _g) = create_temp_pam("account sufficient pam_permit.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:permit_bypass");
}

#[test]
fn test_pam_custom_rogue_module() {
    let (p, _g) = create_temp_pam("auth required /opt/backdoor/pam_stealer.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:custom_module_path");
    assert_eq!(evs[0].processname, "/opt/backdoor/pam_stealer.so");
}

#[test]
fn test_pam_benign_unix_so() {
    let (p, _g) = create_temp_pam("auth [success=1 default=ignore] pam_unix.so nullok\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pam_benign_standard_lib_security() {
    let (p, _g) = create_temp_pam("auth required /lib/security/pam_unix.so\naccount required /lib64/security/pam_deny.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pam_benign_usr_lib_security() {
    let (p, _g) = create_temp_pam("session required /usr/lib/security/pam_limits.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pam_comments_ignored() {
    let (p, _g) = create_temp_pam("# auth optional pam_exec.so /tmp/hook.sh\n# comment\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pam_empty_file_err() {
    let (p, _g) = create_temp_pam("");
    let err = parse_pam_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_pam_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/common-auth");
    let err = parse_pam_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_pam_multiple_hooks() {
    let content = "auth optional pam_exec.so /bin/1\nsession optional pam_exec.so /bin/2\n";
    let (p, _g) = create_temp_pam(content);
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_pam_subject_root() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so /bin/cmd\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_pam_parent_is_pam() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so /bin/cmd\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "pam");
}

#[test]
fn test_pam_line_number_in_commandline() {
    let (p, _g) = create_temp_pam("# 1\n# 2\nauth optional pam_exec.so /bin/cmd\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("line 3"));
}

#[test]
fn test_pam_exec_with_expose_authtok() {
    let (p, _g) = create_temp_pam("password optional pam_exec.so expose_authtok /tmp/sniff.sh\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("expose_authtok"));
}

#[test]
fn test_pam_custom_root_module() {
    let (p, _g) = create_temp_pam("auth required /root/pam_custom.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:custom_module_path");
}

#[test]
fn test_pam_custom_var_tmp_module() {
    let (p, _g) = create_temp_pam("auth required /var/tmp/libpam.so\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:pam:custom_module_path");
}

#[test]
fn test_pam_event_id_zero() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so /bin/c\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_pam_pid_zero() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so /bin/c\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_pam_target_user_root() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so /bin/c\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_pam_computer_name() {
    let (p, _g) = create_temp_pam("auth optional pam_exec.so /bin/c\n");
    let evs = parse_pam_file(&p, "TARGET_HOST").unwrap();
    assert_eq!(evs[0].computer, "TARGET_HOST");
}

#[test]
fn test_pam_tokens_too_short_ignored() {
    let (p, _g) = create_temp_pam("auth\naccount\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pam_both_permit_and_exec() {
    let content = "auth sufficient pam_permit.so\nauth optional pam_exec.so /bin/c\n";
    let (p, _g) = create_temp_pam(content);
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_pam_exec_password_service() {
    let (p, _g) = create_temp_pam("password requisite pam_exec.so /bin/check_pass\n");
    let evs = parse_pam_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}
