use faramir::errors::FaramirError;
use std::io::{Error, ErrorKind};

// ─── System & I/O Error Tests (1000..1999) ───────────────────────────────────

#[test]
fn test_err_sys_io() {
    let err = FaramirError::IoError("Disk read failure".into());
    assert_eq!(err.code(), "ERR_SYS_IO");
    assert_eq!(err.error_number(), 1001);
    assert!(err.to_string().contains("ERR_SYS_IO"));
    assert!(err.to_string().contains("1001"));
}

#[test]
fn test_err_sys_not_found() {
    let err = FaramirError::NotFound("/path/to/missing".into());
    assert_eq!(err.code(), "ERR_SYS_NOT_FOUND");
    assert_eq!(err.error_number(), 1002);
}

#[test]
fn test_err_sys_permission() {
    let err = FaramirError::PermissionDenied("/root/protected".into());
    assert_eq!(err.code(), "ERR_SYS_PERMISSION");
    assert_eq!(err.error_number(), 1003);
}

#[test]
fn test_err_sys_empty_file() {
    let err = FaramirError::EmptyFile("/tmp/empty.txt".into());
    assert_eq!(err.code(), "ERR_SYS_EMPTY_FILE");
    assert_eq!(err.error_number(), 1004);
}

// ─── Ingest & Disk Image Error Tests (2000..2999) ────────────────────────────

#[test]
fn test_err_ing_image_open() {
    let err = FaramirError::ImageOpenFailed("Corrupted disk image".into());
    assert_eq!(err.code(), "ERR_ING_IMAGE_OPEN");
    assert_eq!(err.error_number(), 2001);
}

#[test]
fn test_err_ing_ewf_init() {
    let err = FaramirError::EwfInitFailed("EWF segment missing".into());
    assert_eq!(err.code(), "ERR_ING_EWF_OPEN");
    assert_eq!(err.error_number(), 2002);
}

#[test]
fn test_err_ing_no_ntfs_partition() {
    let err = FaramirError::NoNtfsPartition("/images/disk.raw".into());
    assert_eq!(err.code(), "ERR_ING_NO_NTFS_PARTITION");
    assert_eq!(err.error_number(), 2003);
}

#[test]
fn test_err_ing_bitlocker_locked() {
    let err = FaramirError::BitLockerEncrypted("partition_1".into());
    assert_eq!(err.code(), "ERR_ING_BITLOCKER_LOCKED");
    assert_eq!(err.error_number(), 2004);
}

#[test]
fn test_err_ing_ntfs_parse() {
    let err = FaramirError::NtfsParseError("Boot sector magic invalid".into());
    assert_eq!(err.code(), "ERR_ING_NTFS_PARSE");
    assert_eq!(err.error_number(), 2005);
}

#[test]
fn test_err_ing_ntfs_upcase() {
    let err = FaramirError::NtfsUpcaseError("Cannot read $UpCase".into());
    assert_eq!(err.code(), "ERR_ING_NTFS_UPCASE");
    assert_eq!(err.error_number(), 2006);
}

#[test]
fn test_err_ing_ntfs_root_dir() {
    let err = FaramirError::NtfsRootDirError("Root directory MFT record invalid".into());
    assert_eq!(err.code(), "ERR_ING_NTFS_ROOT_DIR");
    assert_eq!(err.error_number(), 2007);
}

#[test]
fn test_err_ing_ntfs_path_not_found() {
    let err = FaramirError::NtfsPathNotFound("System32/config".into());
    assert_eq!(err.code(), "ERR_ING_NTFS_NAVIGATE");
    assert_eq!(err.error_number(), 2008);
}

#[test]
fn test_err_ing_ntfs_data_stream() {
    let err = FaramirError::NtfsDataStreamError("SAM".into());
    assert_eq!(err.code(), "ERR_ING_NTFS_DATA_STREAM");
    assert_eq!(err.error_number(), 2009);
}

#[test]
fn test_err_ing_archive_open() {
    let err = FaramirError::ArchiveOpenFailed("triage.zip".into());
    assert_eq!(err.code(), "ERR_ING_ARCHIVE_OPEN");
    assert_eq!(err.error_number(), 2010);
}

#[test]
fn test_err_ing_archive_corrupt() {
    let err = FaramirError::ArchiveCorrupt("Unexpected EOF in tar stream".into());
    assert_eq!(err.code(), "ERR_ING_ARCHIVE_CORRUPT");
    assert_eq!(err.error_number(), 2011);
}

#[test]
fn test_err_ing_archive_unpack() {
    let err = FaramirError::ArchiveUnpackError("Cannot extract entry".into());
    assert_eq!(err.code(), "ERR_ING_ARCHIVE_UNPACK");
    assert_eq!(err.error_number(), 2012);
}

#[test]
fn test_err_ing_staging_dir() {
    let err = FaramirError::StagingDirFailed("Permission denied creating temp staging".into());
    assert_eq!(err.code(), "ERR_ING_STAGING_CREATE");
    assert_eq!(err.error_number(), 2013);
}

#[test]
fn test_err_ing_vss_parse() {
    let err = FaramirError::VssParseError("VSS catalog invalid".into());
    assert_eq!(err.code(), "ERR_ING_VSS_PARSE");
    assert_eq!(err.error_number(), 2014);
}

// ─── Windows Registry & Persistence Error Tests (3000..3999) ─────────────────

#[test]
fn test_err_win_hive_open() {
    let err = FaramirError::HiveOpenFailed("SYSTEM".into());
    assert_eq!(err.code(), "ERR_WIN_HIVE_OPEN");
    assert_eq!(err.error_number(), 3001);
}

#[test]
fn test_err_win_hive_corrupt() {
    let err = FaramirError::HiveCorrupt("SOFTWARE".into());
    assert_eq!(err.code(), "ERR_WIN_HIVE_CORRUPT");
    assert_eq!(err.error_number(), 3002);
}

#[test]
fn test_err_win_hive_dirty() {
    let err = FaramirError::HiveDirtyNoLogs("SAM".into());
    assert_eq!(err.code(), "ERR_WIN_HIVE_DIRTY");
    assert_eq!(err.error_number(), 3003);
}

#[test]
fn test_err_win_tx_log_replay() {
    let err = FaramirError::TxLogReplayFailed(".LOG1 sequence mismatch".into());
    assert_eq!(err.code(), "ERR_WIN_TX_LOG_REPLAY");
    assert_eq!(err.error_number(), 3004);
}

#[test]
fn test_err_win_root_key() {
    let err = FaramirError::HiveRootKeyFailed("SECURITY".into());
    assert_eq!(err.code(), "ERR_WIN_ROOT_KEY_FAIL");
    assert_eq!(err.error_number(), 3005);
}

#[test]
fn test_err_win_key_not_found() {
    let err = FaramirError::KeyNotFound(r"Software\Microsoft\Windows\CurrentVersion\Run".into());
    assert_eq!(err.code(), "ERR_WIN_KEY_NOT_FOUND");
    assert_eq!(err.error_number(), 3006);
}

#[test]
fn test_err_win_subkeys_fail() {
    let err = FaramirError::SubkeysEnumFailed(r"Classes\CLSID".into());
    assert_eq!(err.code(), "ERR_WIN_SUBKEYS_FAIL");
    assert_eq!(err.error_number(), 3007);
}

#[test]
fn test_err_win_value_not_found() {
    let err = FaramirError::ValueNotFound("Debugger".into());
    assert_eq!(err.code(), "ERR_WIN_VALUE_NOT_FOUND");
    assert_eq!(err.error_number(), 3008);
}

#[test]
fn test_err_win_value_type_mismatch() {
    let err = FaramirError::ValueTypeMismatch("Expected RegSZ, got RegDWord".into());
    assert_eq!(err.code(), "ERR_WIN_VALUE_TYPE_MISMATCH");
    assert_eq!(err.error_number(), 3009);
}

#[test]
fn test_err_win_control_set_fail() {
    let err = FaramirError::CurrentControlSetFailed("Select key missing".into());
    assert_eq!(err.code(), "ERR_WIN_CONTROL_SET_FAIL");
    assert_eq!(err.error_number(), 3010);
}

#[test]
fn test_err_win_task_xml_parse() {
    let err = FaramirError::TaskXmlParseError("Invalid XML syntax".into());
    assert_eq!(err.code(), "ERR_WIN_TASK_XML_PARSE");
    assert_eq!(err.error_number(), 3011);
}

#[test]
fn test_err_win_task_xml_missing_exec() {
    let err = FaramirError::TaskXmlMissingExec("Task1.xml".into());
    assert_eq!(err.code(), "ERR_WIN_TASK_SCHEMA_INVALID");
    assert_eq!(err.error_number(), 3012);
}

#[test]
fn test_err_win_terminal_json() {
    let err = FaramirError::TerminalJsonParseError("Malformed JSON in settings.json".into());
    assert_eq!(err.code(), "ERR_WIN_TERMINAL_JSON_PARSE");
    assert_eq!(err.error_number(), 3013);
}

#[test]
fn test_err_win_startup_dir() {
    let err = FaramirError::StartupDirReadError("Users\\Admin\\Startup".into());
    assert_eq!(err.code(), "ERR_WIN_STARTUP_DIR_READ");
    assert_eq!(err.error_number(), 3014);
}

#[test]
fn test_err_win_print_monitors() {
    let err = FaramirError::PrintMonitorsFailed("Print key inaccessible".into());
    assert_eq!(err.code(), "ERR_WIN_PRINT_MONITOR_FAIL");
    assert_eq!(err.error_number(), 3015);
}

#[test]
fn test_err_win_time_providers() {
    let err = FaramirError::TimeProvidersFailed("W32Time key error".into());
    assert_eq!(err.code(), "ERR_WIN_TIME_PROVIDER_FAIL");
    assert_eq!(err.error_number(), 3016);
}

#[test]
fn test_err_win_netsh() {
    let err = FaramirError::NetshFailed("Netsh key error".into());
    assert_eq!(err.code(), "ERR_WIN_NETSH_FAIL");
    assert_eq!(err.error_number(), 3017);
}

#[test]
fn test_err_win_powershell_profile() {
    let err = FaramirError::PowerShellProfileError("Profile read error".into());
    assert_eq!(err.code(), "ERR_WIN_POWERSHELL_PROFILE_FAIL");
    assert_eq!(err.error_number(), 3018);
}

// ─── Linux Persistence Error Tests (4000..4999) ──────────────────────────────

#[test]
fn test_err_lnx_cron_syntax() {
    let err = FaramirError::CronSyntax("crontab: bad fields".into());
    assert_eq!(err.code(), "ERR_LNX_CRON_SYNTAX");
    assert_eq!(err.error_number(), 4001);
}

#[test]
fn test_err_lnx_cron_no_user() {
    let err = FaramirError::CronNoUser("no user in system crontab".into());
    assert_eq!(err.code(), "ERR_LNX_CRON_NO_USER");
    assert_eq!(err.error_number(), 4002);
}

#[test]
fn test_err_lnx_cron_no_command() {
    let err = FaramirError::CronNoCommand("@reboot".into());
    assert_eq!(err.code(), "ERR_LNX_CRON_NO_CMD");
    assert_eq!(err.error_number(), 4003);
}

#[test]
fn test_err_lnx_anacron_syntax() {
    let err = FaramirError::AnacronSyntax("anacrontab bad delay".into());
    assert_eq!(err.code(), "ERR_LNX_ANACRON_INVALID");
    assert_eq!(err.error_number(), 4004);
}

#[test]
fn test_err_lnx_systemd_no_section() {
    let err = FaramirError::SystemdNoSection("test.service".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_UNIT");
    assert_eq!(err.error_number(), 4005);
}

#[test]
fn test_err_lnx_systemd_no_exec() {
    let err = FaramirError::SystemdNoExec("test.service".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_EXEC");
    assert_eq!(err.error_number(), 4006);
}

#[test]
fn test_err_lnx_systemd_syntax() {
    let err = FaramirError::SystemdSyntax("ini key error".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_SYNTAX");
    assert_eq!(err.error_number(), 4007);
}

#[test]
fn test_err_lnx_systemd_generator() {
    let err = FaramirError::SystemdGeneratorError("gen.sh".into());
    assert_eq!(err.code(), "ERR_LNX_SYS_GEN_NOT_EXEC");
    assert_eq!(err.error_number(), 4008);
}

#[test]
fn test_err_lnx_shell_syntax() {
    let err = FaramirError::ShellProfileSyntax("unexpected token".into());
    assert_eq!(err.code(), "ERR_LNX_SHELL_SYNTAX");
    assert_eq!(err.error_number(), 4009);
}

#[test]
fn test_err_lnx_ld_preload_invalid() {
    let err = FaramirError::LdPreloadInvalid("relative path".into());
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_INVALID");
    assert_eq!(err.error_number(), 4010);
}

#[test]
fn test_err_lnx_ld_preload_empty() {
    let err = FaramirError::LdPreloadEmpty("ld.so.preload".into());
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_EMPTY");
    assert_eq!(err.error_number(), 4011);
}

#[test]
fn test_err_lnx_ssh_key_invalid() {
    let err = FaramirError::SshKeyInvalid("garbage key".into());
    assert_eq!(err.code(), "ERR_LNX_SSH_KEY_INVALID");
    assert_eq!(err.error_number(), 4012);
}

#[test]
fn test_err_lnx_ssh_config_syntax() {
    let err = FaramirError::SshConfigSyntax("bad option".into());
    assert_eq!(err.code(), "ERR_LNX_SSH_CFG_SYNTAX");
    assert_eq!(err.error_number(), 4013);
}

#[test]
fn test_err_lnx_sudoers_syntax() {
    let err = FaramirError::SudoersSyntax("invalid sudo rule".into());
    assert_eq!(err.code(), "ERR_LNX_SUDO_SYNTAX");
    assert_eq!(err.error_number(), 4014);
}

#[test]
fn test_err_lnx_pam_syntax() {
    let err = FaramirError::PamSyntax("pam token mismatch".into());
    assert_eq!(err.code(), "ERR_LNX_PAM_SYNTAX");
    assert_eq!(err.error_number(), 4015);
}

#[test]
fn test_err_lnx_udev_syntax() {
    let err = FaramirError::UdevSyntax("bad udev match".into());
    assert_eq!(err.code(), "ERR_LNX_UDEV_SYNTAX");
    assert_eq!(err.error_number(), 4016);
}

#[test]
fn test_err_lnx_kernel_module() {
    let err = FaramirError::KernelModuleSyntax("bad mod line".into());
    assert_eq!(err.code(), "ERR_LNX_MOD_SYNTAX");
    assert_eq!(err.error_number(), 4017);
}

#[test]
fn test_err_lnx_pkg_hook() {
    let err = FaramirError::PackageHookSyntax("bad apt block".into());
    assert_eq!(err.code(), "ERR_LNX_PKG_SYNTAX");
    assert_eq!(err.error_number(), 4018);
}

#[test]
fn test_err_lnx_xdg_no_exec() {
    let err = FaramirError::XdgNoExec("app.desktop".into());
    assert_eq!(err.code(), "ERR_LNX_XDG_NO_EXEC");
    assert_eq!(err.error_number(), 4019);
}

#[test]
fn test_err_lnx_xdg_syntax() {
    let err = FaramirError::XdgSyntax("missing Desktop Entry".into());
    assert_eq!(err.code(), "ERR_LNX_XDG_SYNTAX");
    assert_eq!(err.error_number(), 4020);
}

#[test]
fn test_err_lnx_proc_parse() {
    let err = FaramirError::ProcParseError("corrupt exe target".into());
    assert_eq!(err.code(), "ERR_LNX_PROC_PARSE");
    assert_eq!(err.error_number(), 4021);
}

// ─── Timeline Output & CSV Error Tests (5000..5999) ──────────────────────────

#[test]
fn test_err_out_file_create() {
    let err = FaramirError::OutFileCreateFailed("timeline.csv".into());
    assert_eq!(err.code(), "ERR_OUT_FILE_CREATE");
    assert_eq!(err.error_number(), 5001);
}

#[test]
fn test_err_out_csv_write() {
    let err = FaramirError::OutCsvWriteError("Broken pipe".into());
    assert_eq!(err.code(), "ERR_OUT_CSV_WRITE");
    assert_eq!(err.error_number(), 5002);
}

#[test]
fn test_err_out_csv_flush() {
    let err = FaramirError::OutCsvFlushFailed("Disk full".into());
    assert_eq!(err.code(), "ERR_OUT_CSV_FLUSH");
    assert_eq!(err.error_number(), 5003);
}

#[test]
fn test_err_out_dir_create() {
    let err = FaramirError::OutDirCreateFailed("C:\\Protected\\Dir".into());
    assert_eq!(err.code(), "ERR_OUT_DIRECTORY_CREATE");
    assert_eq!(err.error_number(), 5004);
}

// ─── CLI & Argument Validation Error Tests (6000..6999) ──────────────────────

#[test]
fn test_err_cli_no_target() {
    let err = FaramirError::CliNoTarget("Provide -d or -f".into());
    assert_eq!(err.code(), "ERR_CLI_NO_TARGET");
    assert_eq!(err.error_number(), 6001);
}

#[test]
fn test_err_cli_invalid_action() {
    let err = FaramirError::CliInvalidAction("unknown-action".into());
    assert_eq!(err.code(), "ERR_CLI_INVALID_ACTION");
    assert_eq!(err.error_number(), 6002);
}

#[test]
fn test_err_cli_path_not_found() {
    let err = FaramirError::CliPathNotFound("/missing/target".into());
    assert_eq!(err.code(), "ERR_CLI_PATH_NOT_FOUND");
    assert_eq!(err.error_number(), 6003);
}

// ─── Trait & Helper Tests ────────────────────────────────────────────────────

#[test]
fn test_faramir_err_from_io_not_found() {
    let io_err = Error::new(ErrorKind::NotFound, "not found");
    let err: FaramirError = io_err.into();
    assert_eq!(err.code(), "ERR_SYS_NOT_FOUND");
    assert_eq!(err.error_number(), 1002);
}

#[test]
fn test_faramir_err_from_io_permission() {
    let io_err = Error::new(ErrorKind::PermissionDenied, "access denied");
    let err: FaramirError = io_err.into();
    assert_eq!(err.code(), "ERR_SYS_PERMISSION");
    assert_eq!(err.error_number(), 1003);
}

#[test]
fn test_faramir_err_from_io_other() {
    let io_err = Error::new(ErrorKind::Interrupted, "interrupted");
    let err: FaramirError = io_err.into();
    assert_eq!(err.code(), "ERR_SYS_IO");
    assert_eq!(err.error_number(), 1001);
}

#[test]
fn test_faramir_err_clone_and_eq() {
    let err1 = FaramirError::NoNtfsPartition("disk.e01".into());
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_faramir_err_display_format() {
    let err = FaramirError::BitLockerEncrypted("partition_2".into());
    let s = format!("{}", err);
    assert!(s.contains("ERR_ING_BITLOCKER_LOCKED"));
    assert!(s.contains("2004"));
    assert!(s.contains("partition_2"));
}

#[test]
fn test_faramir_err_std_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(FaramirError::OutCsvFlushFailed("flush err".into()));
    assert!(!err.to_string().is_empty());
}
