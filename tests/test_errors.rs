use faramir::parsers::linux::error::LinuxPersistenceError;
use std::io::{Error, ErrorKind};

#[test]
fn test_err_file_not_found_code() {
    let err = LinuxPersistenceError::FileNotFound("/etc/crontab".into());
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
    assert_eq!(err.error_number(), 1001);
    assert!(err.to_string().contains("ERR_LNX_IO_NOT_FOUND"));
    assert!(err.to_string().contains("1001"));
}

#[test]
fn test_err_permission_denied_code() {
    let err = LinuxPersistenceError::PermissionDenied("/etc/shadow".into());
    assert_eq!(err.code(), "ERR_LNX_IO_PERMISSION");
    assert_eq!(err.error_number(), 1002);
    assert!(err.to_string().contains("ERR_LNX_IO_PERMISSION"));
}

#[test]
fn test_err_generic_io_code() {
    let err = LinuxPersistenceError::IoError("Disk failure".into());
    assert_eq!(err.code(), "ERR_LNX_IO_GENERIC");
    assert_eq!(err.error_number(), 1003);
}

#[test]
fn test_err_empty_file_code() {
    let err = LinuxPersistenceError::EmptyFile("/etc/ld.so.preload".into());
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
    assert_eq!(err.error_number(), 1004);
}

#[test]
fn test_err_cron_syntax_code() {
    let err = LinuxPersistenceError::InvalidCronSyntax("crontab: bad fields".into());
    assert_eq!(err.code(), "ERR_LNX_CRON_SYNTAX");
    assert_eq!(err.error_number(), 2001);
}

#[test]
fn test_err_cron_no_user_code() {
    let err = LinuxPersistenceError::MissingCronUser("user field missing".into());
    assert_eq!(err.code(), "ERR_LNX_CRON_NO_USER");
    assert_eq!(err.error_number(), 2002);
}

#[test]
fn test_err_cron_no_cmd_code() {
    let err = LinuxPersistenceError::MissingCronCommand("no command specified".into());
    assert_eq!(err.code(), "ERR_LNX_CRON_NO_CMD");
    assert_eq!(err.error_number(), 2003);
}

#[test]
fn test_err_anacron_invalid_code() {
    let err = LinuxPersistenceError::InvalidAnacronEntry("bad anacron".into());
    assert_eq!(err.code(), "ERR_LNX_ANACRON_INVALID");
    assert_eq!(err.error_number(), 2004);
}

#[test]
fn test_err_systemd_no_unit_code() {
    let err = LinuxPersistenceError::SystemdMissingUnitSection("test.service".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_UNIT");
    assert_eq!(err.error_number(), 3001);
}

#[test]
fn test_err_systemd_no_exec_code() {
    let err = LinuxPersistenceError::SystemdMissingExec("test.service".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_EXEC");
    assert_eq!(err.error_number(), 3002);
}

#[test]
fn test_err_systemd_syntax_code() {
    let err = LinuxPersistenceError::SystemdSyntaxError("corrupt ini".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_SYNTAX");
    assert_eq!(err.error_number(), 3003);
}

#[test]
fn test_err_systemd_generator_code() {
    let err = LinuxPersistenceError::SystemdGeneratorInvalid("gen.sh".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_GEN_NOT_EXEC");
    assert_eq!(err.error_number(), 3004);
}

#[test]
fn test_err_shell_empty_code() {
    let err = LinuxPersistenceError::ShellProfileEmpty("~/.bashrc".into());
    assert_eq!(err.code(), "ERR_LNX_SHELL_EMPTY");
    assert_eq!(err.error_number(), 4001);
}

#[test]
fn test_err_shell_syntax_code() {
    let err = LinuxPersistenceError::ShellProfileSyntax("unexpected EOF".into());
    assert_eq!(err.code(), "ERR_LNX_SHELL_SYNTAX");
    assert_eq!(err.error_number(), 4002);
}

#[test]
fn test_err_ld_preload_invalid_code() {
    let err = LinuxPersistenceError::LdPreloadInvalidEntry("relative path".into());
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_INVALID");
    assert_eq!(err.error_number(), 5001);
}

#[test]
fn test_err_ld_preload_empty_code() {
    let err = LinuxPersistenceError::LdPreloadEmpty("/etc/ld.so.preload".into());
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_EMPTY");
    assert_eq!(err.error_number(), 5002);
}

#[test]
fn test_err_ssh_key_invalid_code() {
    let err = LinuxPersistenceError::SshKeyInvalid("garbage key".into());
    assert_eq!(err.code(), "ERR_LNX_SSH_KEY_INVALID");
    assert_eq!(err.error_number(), 6001);
}

#[test]
fn test_err_ssh_cfg_syntax_code() {
    let err = LinuxPersistenceError::SshConfigSyntax("bad option".into());
    assert_eq!(err.code(), "ERR_LNX_SSH_CFG_SYNTAX");
    assert_eq!(err.error_number(), 6002);
}

#[test]
fn test_err_sudoers_syntax_code() {
    let err = LinuxPersistenceError::SudoersSyntax("invalid token".into());
    assert_eq!(err.code(), "ERR_LNX_SUDO_SYNTAX");
    assert_eq!(err.error_number(), 7001);
}

#[test]
fn test_err_sudoers_incomplete_code() {
    let err = LinuxPersistenceError::SudoersIncomplete("missing command".into());
    assert_eq!(err.code(), "ERR_LNX_SUDO_INCOMPLETE");
    assert_eq!(err.error_number(), 7002);
}

#[test]
fn test_err_pam_syntax_code() {
    let err = LinuxPersistenceError::PamSyntax("missing type".into());
    assert_eq!(err.code(), "ERR_LNX_PAM_SYNTAX");
    assert_eq!(err.error_number(), 8001);
}

#[test]
fn test_err_pam_missing_flag_code() {
    let err = LinuxPersistenceError::PamMissingFlag("missing requisite".into());
    assert_eq!(err.code(), "ERR_LNX_PAM_NO_FLAG");
    assert_eq!(err.error_number(), 8002);
}

#[test]
fn test_err_udev_syntax_code() {
    let err = LinuxPersistenceError::UdevSyntax("bad matcher".into());
    assert_eq!(err.code(), "ERR_LNX_UDEV_SYNTAX");
    assert_eq!(err.error_number(), 9001);
}

#[test]
fn test_err_udev_no_run_code() {
    let err = LinuxPersistenceError::UdevNoRunAction("missing RUN+=".into());
    assert_eq!(err.code(), "ERR_LNX_UDEV_NO_RUN");
    assert_eq!(err.error_number(), 9002);
}

#[test]
fn test_err_kernel_mod_syntax_code() {
    let err = LinuxPersistenceError::KernelModuleSyntax("bad mod line".into());
    assert_eq!(err.code(), "ERR_LNX_MOD_SYNTAX");
    assert_eq!(err.error_number(), 10001);
}

#[test]
fn test_err_pkg_hook_syntax_code() {
    let err = LinuxPersistenceError::PackageHookSyntax("bad invocation block".into());
    assert_eq!(err.code(), "ERR_LNX_PKG_SYNTAX");
    assert_eq!(err.error_number(), 11001);
}

#[test]
fn test_err_xdg_no_exec_code() {
    let err = LinuxPersistenceError::XdgMissingExec("test.desktop".into());
    assert_eq!(err.code(), "ERR_LNX_XDG_NO_EXEC");
    assert_eq!(err.error_number(), 12001);
}

#[test]
fn test_err_xdg_syntax_code() {
    let err = LinuxPersistenceError::XdgSyntax("missing Desktop Entry".into());
    assert_eq!(err.code(), "ERR_LNX_XDG_SYNTAX");
    assert_eq!(err.error_number(), 12002);
}

#[test]
fn test_err_proc_parse_code() {
    let err = LinuxPersistenceError::ProcParseError("corrupted link target".into());
    assert_eq!(err.code(), "ERR_LNX_PROC_PARSE");
    assert_eq!(err.error_number(), 13001);
}

#[test]
fn test_err_from_io_not_found() {
    let io_err = Error::new(ErrorKind::NotFound, "No such file");
    let err: LinuxPersistenceError = io_err.into();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
    assert_eq!(err.error_number(), 1001);
}

#[test]
fn test_err_from_io_permission_denied() {
    let io_err = Error::new(ErrorKind::PermissionDenied, "Access denied");
    let err: LinuxPersistenceError = io_err.into();
    assert_eq!(err.code(), "ERR_LNX_IO_PERMISSION");
    assert_eq!(err.error_number(), 1002);
}

#[test]
fn test_err_from_io_other() {
    let io_err = Error::new(ErrorKind::UnexpectedEof, "Eof reached");
    let err: LinuxPersistenceError = io_err.into();
    assert_eq!(err.code(), "ERR_LNX_IO_GENERIC");
    assert_eq!(err.error_number(), 1003);
}

#[test]
fn test_err_clone_and_eq() {
    let err1 = LinuxPersistenceError::FileNotFound("test".into());
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_err_display_contains_message() {
    let err = LinuxPersistenceError::InvalidCronSyntax("custom error detail".into());
    let formatted = format!("{}", err);
    assert!(formatted.contains("custom error detail"));
}

#[test]
fn test_err_trait_impl() {
    let err: Box<dyn std::error::Error> = Box::new(LinuxPersistenceError::EmptyFile("f".into()));
    assert!(!err.to_string().is_empty());
}
