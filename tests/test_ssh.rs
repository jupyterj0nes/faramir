use faramir::parsers::linux::ssh::*;
use std::fs::File;
use std::io::Write;

fn create_temp_ssh(content: &str, name: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("{}_{}_{}.ssh", name, std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
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

// ─── Authorized Keys Tests ────────────────────────────────────────────────────

#[test]
fn test_ssh_key_rsa() {
    let (p, _g) = create_temp_ssh("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:ssh:authorized_key");
    assert!(evs[0].commandline.as_ref().unwrap().contains("ssh-rsa"));
}

#[test]
fn test_ssh_key_ed25519() {
    let (p, _g) = create_temp_ssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@laptop\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].commandline.as_ref().unwrap().contains("ssh-ed25519"));
}

#[test]
fn test_ssh_key_dss() {
    let (p, _g) = create_temp_ssh("ssh-dss AAAAB3NzaC1kc3MAAACBA... old_key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_ecdsa_256() {
    let (p, _g) = create_temp_ssh("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_ecdsa_384() {
    let (p, _g) = create_temp_ssh("ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_ecdsa_521() {
    let (p, _g) = create_temp_ssh("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjE... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_sk_ed25519() {
    let (p, _g) = create_temp_ssh("sk-ssh-ed25519@openssh.com AAAA... security_key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_with_command_option() {
    let (p, _g) = create_temp_ssh("command=\"/usr/local/bin/validate.sh\" ssh-rsa AAAA... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].commandline.as_ref().unwrap().contains("command="));
}

#[test]
fn test_ssh_key_with_from_option() {
    let (p, _g) = create_temp_ssh("from=\"192.168.1.0/24\" ssh-ed25519 AAAA... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].commandline.as_ref().unwrap().contains("from="));
}

#[test]
fn test_ssh_key_with_multiple_options() {
    let (p, _g) = create_temp_ssh("no-port-forwarding,no-X11-forwarding ssh-rsa AAAA... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_multiple_keys() {
    let (p, _g) = create_temp_ssh("ssh-rsa AAAA... key1\nssh-ed25519 BBBB... key2\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_ssh_key_ignores_comments() {
    let (p, _g) = create_temp_ssh("# Admin key\nssh-rsa AAAA... admin\n# Backup\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ssh_key_invalid_format_err() {
    let (p, _g) = create_temp_ssh("not-a-valid-ssh-key-line-at-all\n", "auth_keys");
    let err = parse_ssh_authorized_keys(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SSH_KEY_INVALID");
    assert_eq!(err.error_number(), 6001);
}

#[test]
fn test_ssh_key_empty_file_err() {
    let (p, _g) = create_temp_ssh("", "auth_keys");
    let err = parse_ssh_authorized_keys(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_ssh_key_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/authorized_keys");
    let err = parse_ssh_authorized_keys(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_ssh_key_parent_is_sshd() {
    let (p, _g) = create_temp_ssh("ssh-rsa AAAA... key\n", "auth_keys");
    let evs = parse_ssh_authorized_keys(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "sshd");
}

// ─── sshd_config Tests ────────────────────────────────────────────────────────

#[test]
fn test_sshd_config_authorized_keys_command() {
    let (p, _g) = create_temp_ssh("AuthorizedKeysCommand /usr/local/bin/fetch_keys %u\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:ssh:authorized_keys_command");
    assert!(evs[0].commandline.as_ref().unwrap().contains("fetch_keys"));
}

#[test]
fn test_sshd_config_force_command() {
    let (p, _g) = create_temp_ssh("ForceCommand /opt/audit_shell.sh\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:ssh:force_command");
    assert!(evs[0].commandline.as_ref().unwrap().contains("audit_shell.sh"));
}

#[test]
fn test_sshd_config_both_commands() {
    let (p, _g) = create_temp_ssh("AuthorizedKeysCommand /bin/cmd1\nForceCommand /bin/cmd2\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_sshd_config_none_ignored() {
    let (p, _g) = create_temp_ssh("AuthorizedKeysCommand none\nForceCommand NONE\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_sshd_config_ignores_comments() {
    let (p, _g) = create_temp_ssh("# AuthorizedKeysCommand /bin/hook\nPort 22\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_sshd_config_empty_file_err() {
    let (p, _g) = create_temp_ssh("", "sshd_cfg");
    let err = parse_sshd_config(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_sshd_config_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/sshd_config");
    let err = parse_sshd_config(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_sshd_config_case_insensitive() {
    let (p, _g) = create_temp_ssh("authorizedkeyscommand /opt/get.sh\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_sshd_config_subject_root() {
    let (p, _g) = create_temp_ssh("ForceCommand /bin/cmd\n", "sshd_cfg");
    let evs = parse_sshd_config(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}
