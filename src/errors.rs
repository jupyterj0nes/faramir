use std::fmt;
use std::io;

/// Master error code enumeration for Faramir
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FaramirError {
    // ─── 1000..1999: System & I/O ───────────────────────────────────────────
    /// Generic I/O error (1001)
    IoError(String),
    /// File or directory not found (1002)
    NotFound(String),
    /// Permission denied (1003)
    PermissionDenied(String),
    /// Empty or 0-byte file (1004)
    EmptyFile(String),

    // ─── 2000..2999: Ingest & Disk Images ───────────────────────────────────
    /// Failed to open forensic disk image (2001)
    ImageOpenFailed(String),
    /// Failed to initialize E01 / Expert Witness reader (2002)
    EwfInitFailed(String),
    /// No NTFS partition discovered (2003)
    NoNtfsPartition(String),
    /// Partition is BitLocker encrypted (2004)
    BitLockerEncrypted(String),
    /// NTFS filesystem structure parsing error (2005)
    NtfsParseError(String),
    /// NTFS upcase table reading failure (2006)
    NtfsUpcaseError(String),
    /// Failed to locate root directory in NTFS (2007)
    NtfsRootDirError(String),
    /// Failed to navigate NTFS directory path (2008)
    NtfsPathNotFound(String),
    /// NTFS file has no valid standard data stream (2009)
    NtfsDataStreamError(String),
    /// Archive file cannot be opened (2010)
    ArchiveOpenFailed(String),
    /// Archive decompression error or corrupt entry (2011)
    ArchiveCorrupt(String),
    /// Failed to unpack entry from archive (2012)
    ArchiveUnpackError(String),
    /// Staging directory creation failed (2013)
    StagingDirFailed(String),
    /// Volume Shadow Copy (VSS) parsing failed (2014)
    VssParseError(String),

    // ─── 3000..3999: Windows Registry & Persistence ─────────────────────────
    /// Failed to open registry hive (3001)
    HiveOpenFailed(String),
    /// Hive header or block corrupted (3002)
    HiveCorrupt(String),
    /// Dirty hive detected without transaction logs (3003)
    HiveDirtyNoLogs(String),
    /// Transaction log replay failure (3004)
    TxLogReplayFailed(String),
    /// Hive root key node inaccessible (3005)
    HiveRootKeyFailed(String),
    /// Registry key path not found (3006)
    KeyNotFound(String),
    /// Failed to enumerate registry subkeys (3007)
    SubkeysEnumFailed(String),
    /// Registry value not found (3008)
    ValueNotFound(String),
    /// Registry value has unexpected type (3009)
    ValueTypeMismatch(String),
    /// Failed to identify CurrentControlSet (3010)
    CurrentControlSetFailed(String),
    /// Scheduled Task XML parsing failed (3011)
    TaskXmlParseError(String),
    /// Scheduled Task XML missing Exec / Command (3012)
    TaskXmlMissingExec(String),
    /// Windows Terminal settings.json parse error (3013)
    TerminalJsonParseError(String),
    /// Startup directory read error (3014)
    StartupDirReadError(String),
    /// Print Monitors registry enumeration failed (3015)
    PrintMonitorsFailed(String),
    /// Time Providers registry enumeration failed (3016)
    TimeProvidersFailed(String),
    /// Netsh helper DLL enumeration failed (3017)
    NetshFailed(String),
    /// PowerShell profile script error (3018)
    PowerShellProfileError(String),

    // ─── 4000..4999: Linux Persistence ──────────────────────────────────────
    /// Invalid cron syntax (4001)
    CronSyntax(String),
    /// Missing cron user (4002)
    CronNoUser(String),
    /// Missing cron command (4003)
    CronNoCommand(String),
    /// Invalid anacron entry (4004)
    AnacronSyntax(String),
    /// Systemd unit missing section (4005)
    SystemdNoSection(String),
    /// Systemd unit missing ExecStart or trigger (4006)
    SystemdNoExec(String),
    /// Systemd syntax error (4007)
    SystemdSyntax(String),
    /// Systemd generator invalid (4008)
    SystemdGeneratorError(String),
    /// Shell profile syntax error (4009)
    ShellProfileSyntax(String),
    /// LD_PRELOAD invalid entry (4010)
    LdPreloadInvalid(String),
    /// LD_PRELOAD empty file (4011)
    LdPreloadEmpty(String),
    /// SSH authorized_keys line invalid (4012)
    SshKeyInvalid(String),
    /// SSH config syntax error (4013)
    SshConfigSyntax(String),
    /// Sudoers syntax error (4014)
    SudoersSyntax(String),
    /// PAM module syntax error (4015)
    PamSyntax(String),
    /// Udev rule syntax error (4016)
    UdevSyntax(String),
    /// Kernel module syntax error (4017)
    KernelModuleSyntax(String),
    /// Package manager hook syntax error (4018)
    PackageHookSyntax(String),
    /// XDG desktop file missing Exec key (4019)
    XdgNoExec(String),
    /// XDG desktop syntax error (4020)
    XdgSyntax(String),
    /// Proc running process parse error (4021)
    ProcParseError(String),

    // ─── 5000..5999: Timeline Output & CSV ──────────────────────────────────
    /// Output file creation error (5001)
    OutFileCreateFailed(String),
    /// CSV record write error (5002)
    OutCsvWriteError(String),
    /// CSV writer flush failure (5003)
    OutCsvFlushFailed(String),
    /// Output parent directory creation failure (5004)
    OutDirCreateFailed(String),

    // ─── 6000..6999: CLI & Argument Validation ──────────────────────────────
    /// No evidence target provided (6001)
    CliNoTarget(String),
    /// Invalid action requested (6002)
    CliInvalidAction(String),
    /// Target path does not exist (6003)
    CliPathNotFound(String),
}

impl FaramirError {
    /// Returns standardized uppercase text code
    pub fn code(&self) -> &'static str {
        match self {
            Self::IoError(_) => "ERR_SYS_IO",
            Self::NotFound(_) => "ERR_SYS_NOT_FOUND",
            Self::PermissionDenied(_) => "ERR_SYS_PERMISSION",
            Self::EmptyFile(_) => "ERR_SYS_EMPTY_FILE",

            Self::ImageOpenFailed(_) => "ERR_ING_IMAGE_OPEN",
            Self::EwfInitFailed(_) => "ERR_ING_EWF_OPEN",
            Self::NoNtfsPartition(_) => "ERR_ING_NO_NTFS_PARTITION",
            Self::BitLockerEncrypted(_) => "ERR_ING_BITLOCKER_LOCKED",
            Self::NtfsParseError(_) => "ERR_ING_NTFS_PARSE",
            Self::NtfsUpcaseError(_) => "ERR_ING_NTFS_UPCASE",
            Self::NtfsRootDirError(_) => "ERR_ING_NTFS_ROOT_DIR",
            Self::NtfsPathNotFound(_) => "ERR_ING_NTFS_NAVIGATE",
            Self::NtfsDataStreamError(_) => "ERR_ING_NTFS_DATA_STREAM",
            Self::ArchiveOpenFailed(_) => "ERR_ING_ARCHIVE_OPEN",
            Self::ArchiveCorrupt(_) => "ERR_ING_ARCHIVE_CORRUPT",
            Self::ArchiveUnpackError(_) => "ERR_ING_ARCHIVE_UNPACK",
            Self::StagingDirFailed(_) => "ERR_ING_STAGING_CREATE",
            Self::VssParseError(_) => "ERR_ING_VSS_PARSE",

            Self::HiveOpenFailed(_) => "ERR_WIN_HIVE_OPEN",
            Self::HiveCorrupt(_) => "ERR_WIN_HIVE_CORRUPT",
            Self::HiveDirtyNoLogs(_) => "ERR_WIN_HIVE_DIRTY",
            Self::TxLogReplayFailed(_) => "ERR_WIN_TX_LOG_REPLAY",
            Self::HiveRootKeyFailed(_) => "ERR_WIN_ROOT_KEY_FAIL",
            Self::KeyNotFound(_) => "ERR_WIN_KEY_NOT_FOUND",
            Self::SubkeysEnumFailed(_) => "ERR_WIN_SUBKEYS_FAIL",
            Self::ValueNotFound(_) => "ERR_WIN_VALUE_NOT_FOUND",
            Self::ValueTypeMismatch(_) => "ERR_WIN_VALUE_TYPE_MISMATCH",
            Self::CurrentControlSetFailed(_) => "ERR_WIN_CONTROL_SET_FAIL",
            Self::TaskXmlParseError(_) => "ERR_WIN_TASK_XML_PARSE",
            Self::TaskXmlMissingExec(_) => "ERR_WIN_TASK_SCHEMA_INVALID",
            Self::TerminalJsonParseError(_) => "ERR_WIN_TERMINAL_JSON_PARSE",
            Self::StartupDirReadError(_) => "ERR_WIN_STARTUP_DIR_READ",
            Self::PrintMonitorsFailed(_) => "ERR_WIN_PRINT_MONITOR_FAIL",
            Self::TimeProvidersFailed(_) => "ERR_WIN_TIME_PROVIDER_FAIL",
            Self::NetshFailed(_) => "ERR_WIN_NETSH_FAIL",
            Self::PowerShellProfileError(_) => "ERR_WIN_POWERSHELL_PROFILE_FAIL",

            Self::CronSyntax(_) => "ERR_LNX_CRON_SYNTAX",
            Self::CronNoUser(_) => "ERR_LNX_CRON_NO_USER",
            Self::CronNoCommand(_) => "ERR_LNX_CRON_NO_CMD",
            Self::AnacronSyntax(_) => "ERR_LNX_ANACRON_INVALID",
            Self::SystemdNoSection(_) => "ERR_LNX_SYS_NO_UNIT",
            Self::SystemdNoExec(_) => "ERR_LNX_SYS_NO_EXEC",
            Self::SystemdSyntax(_) => "ERR_LNX_SYS_SYNTAX",
            Self::SystemdGeneratorError(_) => "ERR_LNX_SYS_GEN_NOT_EXEC",
            Self::ShellProfileSyntax(_) => "ERR_LNX_SHELL_SYNTAX",
            Self::LdPreloadInvalid(_) => "ERR_LNX_LDPRELOAD_INVALID",
            Self::LdPreloadEmpty(_) => "ERR_LNX_LDPRELOAD_EMPTY",
            Self::SshKeyInvalid(_) => "ERR_LNX_SSH_KEY_INVALID",
            Self::SshConfigSyntax(_) => "ERR_LNX_SSH_CFG_SYNTAX",
            Self::SudoersSyntax(_) => "ERR_LNX_SUDO_SYNTAX",
            Self::PamSyntax(_) => "ERR_LNX_PAM_SYNTAX",
            Self::UdevSyntax(_) => "ERR_LNX_UDEV_SYNTAX",
            Self::KernelModuleSyntax(_) => "ERR_LNX_MOD_SYNTAX",
            Self::PackageHookSyntax(_) => "ERR_LNX_PKG_SYNTAX",
            Self::XdgNoExec(_) => "ERR_LNX_XDG_NO_EXEC",
            Self::XdgSyntax(_) => "ERR_LNX_XDG_SYNTAX",
            Self::ProcParseError(_) => "ERR_LNX_PROC_PARSE",

            Self::OutFileCreateFailed(_) => "ERR_OUT_FILE_CREATE",
            Self::OutCsvWriteError(_) => "ERR_OUT_CSV_WRITE",
            Self::OutCsvFlushFailed(_) => "ERR_OUT_CSV_FLUSH",
            Self::OutDirCreateFailed(_) => "ERR_OUT_DIRECTORY_CREATE",

            Self::CliNoTarget(_) => "ERR_CLI_NO_TARGET",
            Self::CliInvalidAction(_) => "ERR_CLI_INVALID_ACTION",
            Self::CliPathNotFound(_) => "ERR_CLI_PATH_NOT_FOUND",
        }
    }

    /// Returns unique numeric error number
    pub fn error_number(&self) -> u32 {
        match self {
            Self::IoError(_) => 1001,
            Self::NotFound(_) => 1002,
            Self::PermissionDenied(_) => 1003,
            Self::EmptyFile(_) => 1004,

            Self::ImageOpenFailed(_) => 2001,
            Self::EwfInitFailed(_) => 2002,
            Self::NoNtfsPartition(_) => 2003,
            Self::BitLockerEncrypted(_) => 2004,
            Self::NtfsParseError(_) => 2005,
            Self::NtfsUpcaseError(_) => 2006,
            Self::NtfsRootDirError(_) => 2007,
            Self::NtfsPathNotFound(_) => 2008,
            Self::NtfsDataStreamError(_) => 2009,
            Self::ArchiveOpenFailed(_) => 2010,
            Self::ArchiveCorrupt(_) => 2011,
            Self::ArchiveUnpackError(_) => 2012,
            Self::StagingDirFailed(_) => 2013,
            Self::VssParseError(_) => 2014,

            Self::HiveOpenFailed(_) => 3001,
            Self::HiveCorrupt(_) => 3002,
            Self::HiveDirtyNoLogs(_) => 3003,
            Self::TxLogReplayFailed(_) => 3004,
            Self::HiveRootKeyFailed(_) => 3005,
            Self::KeyNotFound(_) => 3006,
            Self::SubkeysEnumFailed(_) => 3007,
            Self::ValueNotFound(_) => 3008,
            Self::ValueTypeMismatch(_) => 3009,
            Self::CurrentControlSetFailed(_) => 3010,
            Self::TaskXmlParseError(_) => 3011,
            Self::TaskXmlMissingExec(_) => 3012,
            Self::TerminalJsonParseError(_) => 3013,
            Self::StartupDirReadError(_) => 3014,
            Self::PrintMonitorsFailed(_) => 3015,
            Self::TimeProvidersFailed(_) => 3016,
            Self::NetshFailed(_) => 3017,
            Self::PowerShellProfileError(_) => 3018,

            Self::CronSyntax(_) => 4001,
            Self::CronNoUser(_) => 4002,
            Self::CronNoCommand(_) => 4003,
            Self::AnacronSyntax(_) => 4004,
            Self::SystemdNoSection(_) => 4005,
            Self::SystemdNoExec(_) => 4006,
            Self::SystemdSyntax(_) => 4007,
            Self::SystemdGeneratorError(_) => 4008,
            Self::ShellProfileSyntax(_) => 4009,
            Self::LdPreloadInvalid(_) => 4010,
            Self::LdPreloadEmpty(_) => 4011,
            Self::SshKeyInvalid(_) => 4012,
            Self::SshConfigSyntax(_) => 4013,
            Self::SudoersSyntax(_) => 4014,
            Self::PamSyntax(_) => 4015,
            Self::UdevSyntax(_) => 4016,
            Self::KernelModuleSyntax(_) => 4017,
            Self::PackageHookSyntax(_) => 4018,
            Self::XdgNoExec(_) => 4019,
            Self::XdgSyntax(_) => 4020,
            Self::ProcParseError(_) => 4021,

            Self::OutFileCreateFailed(_) => 5001,
            Self::OutCsvWriteError(_) => 5002,
            Self::OutCsvFlushFailed(_) => 5003,
            Self::OutDirCreateFailed(_) => 5004,

            Self::CliNoTarget(_) => 6001,
            Self::CliInvalidAction(_) => 6002,
            Self::CliPathNotFound(_) => 6003,
        }
    }
}

impl fmt::Display for FaramirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} - {}] ", self.code(), self.error_number())?;
        match self {
            Self::IoError(e) => write!(f, "System I/O error: {}", e),
            Self::NotFound(p) => write!(f, "Path not found: {}", p),
            Self::PermissionDenied(p) => write!(f, "Permission denied accessing: {}", p),
            Self::EmptyFile(p) => write!(f, "File is zero bytes or empty: {}", p),

            Self::ImageOpenFailed(e) => write!(f, "Failed to open forensic image: {}", e),
            Self::EwfInitFailed(e) => write!(f, "EWF/E01 reader failure: {}", e),
            Self::NoNtfsPartition(p) => write!(f, "No NTFS partitions detected in: {}", p),
            Self::BitLockerEncrypted(p) => write!(f, "Partition is BitLocker encrypted: {}", p),
            Self::NtfsParseError(e) => write!(f, "NTFS structure error: {}", e),
            Self::NtfsUpcaseError(e) => write!(f, "NTFS upcase table error: {}", e),
            Self::NtfsRootDirError(e) => write!(f, "NTFS root directory error: {}", e),
            Self::NtfsPathNotFound(p) => write!(f, "NTFS path component not found: {}", p),
            Self::NtfsDataStreamError(p) => write!(f, "NTFS data stream missing in: {}", p),
            Self::ArchiveOpenFailed(e) => write!(f, "Cannot open archive: {}", e),
            Self::ArchiveCorrupt(e) => write!(f, "Corrupted archive entry: {}", e),
            Self::ArchiveUnpackError(e) => write!(f, "Failed to unpack archive entry: {}", e),
            Self::StagingDirFailed(e) => write!(f, "Cannot initialize staging folder: {}", e),
            Self::VssParseError(e) => write!(f, "VSS parsing failure: {}", e),

            Self::HiveOpenFailed(p) => write!(f, "Failed to open hive: {}", p),
            Self::HiveCorrupt(p) => write!(f, "Registry hive is corrupt: {}", p),
            Self::HiveDirtyNoLogs(p) => write!(f, "Dirty hive without valid transaction logs: {}", p),
            Self::TxLogReplayFailed(e) => write!(f, "Transaction log replay failed: {}", e),
            Self::HiveRootKeyFailed(p) => write!(f, "Failed to acquire root key in: {}", p),
            Self::KeyNotFound(p) => write!(f, "Registry key not found: {}", p),
            Self::SubkeysEnumFailed(p) => write!(f, "Failed to enumerate subkeys in: {}", p),
            Self::ValueNotFound(p) => write!(f, "Registry value not found: {}", p),
            Self::ValueTypeMismatch(p) => write!(f, "Unexpected registry value type in: {}", p),
            Self::CurrentControlSetFailed(p) => write!(f, "Failed to resolve CurrentControlSet in: {}", p),
            Self::TaskXmlParseError(e) => write!(f, "Task XML parse error: {}", e),
            Self::TaskXmlMissingExec(p) => write!(f, "Task XML missing Command/Exec in: {}", p),
            Self::TerminalJsonParseError(e) => write!(f, "Terminal settings.json parse error: {}", e),
            Self::StartupDirReadError(p) => write!(f, "Failed reading Startup folder: {}", p),
            Self::PrintMonitorsFailed(e) => write!(f, "Print monitors error: {}", e),
            Self::TimeProvidersFailed(e) => write!(f, "Time providers error: {}", e),
            Self::NetshFailed(e) => write!(f, "Netsh helper error: {}", e),
            Self::PowerShellProfileError(e) => write!(f, "PowerShell profile error: {}", e),

            Self::CronSyntax(e) => write!(f, "Cron syntax error: {}", e),
            Self::CronNoUser(e) => write!(f, "Cron missing user: {}", e),
            Self::CronNoCommand(e) => write!(f, "Cron missing command: {}", e),
            Self::AnacronSyntax(e) => write!(f, "Anacron entry error: {}", e),
            Self::SystemdNoSection(p) => write!(f, "Systemd unit missing section in: {}", p),
            Self::SystemdNoExec(p) => write!(f, "Systemd unit missing ExecStart/Trigger in: {}", p),
            Self::SystemdSyntax(e) => write!(f, "Systemd unit syntax error: {}", e),
            Self::SystemdGeneratorError(p) => write!(f, "Systemd generator invalid: {}", p),
            Self::ShellProfileSyntax(e) => write!(f, "Shell profile syntax error: {}", e),
            Self::LdPreloadInvalid(e) => write!(f, "LD_PRELOAD invalid entry: {}", e),
            Self::LdPreloadEmpty(p) => write!(f, "LD_PRELOAD is empty: {}", p),
            Self::SshKeyInvalid(e) => write!(f, "SSH key invalid: {}", e),
            Self::SshConfigSyntax(e) => write!(f, "sshd_config syntax error: {}", e),
            Self::SudoersSyntax(e) => write!(f, "Sudoers syntax error: {}", e),
            Self::PamSyntax(e) => write!(f, "PAM rule syntax error: {}", e),
            Self::UdevSyntax(e) => write!(f, "Udev rule syntax error: {}", e),
            Self::KernelModuleSyntax(e) => write!(f, "Kernel module syntax error: {}", e),
            Self::PackageHookSyntax(e) => write!(f, "Package hook syntax error: {}", e),
            Self::XdgNoExec(p) => write!(f, "XDG .desktop missing Exec in: {}", p),
            Self::XdgSyntax(e) => write!(f, "XDG .desktop syntax error: {}", e),
            Self::ProcParseError(e) => write!(f, "Proc parse failure: {}", e),

            Self::OutFileCreateFailed(p) => write!(f, "Cannot create output CSV file: {}", p),
            Self::OutCsvWriteError(e) => write!(f, "CSV record write failure: {}", e),
            Self::OutCsvFlushFailed(e) => write!(f, "CSV buffer flush failure: {}", e),
            Self::OutDirCreateFailed(p) => write!(f, "Cannot create output directory: {}", p),

            Self::CliNoTarget(msg) => write!(f, "No evidence targets provided: {}", msg),
            Self::CliInvalidAction(msg) => write!(f, "Invalid CLI action: {}", msg),
            Self::CliPathNotFound(p) => write!(f, "Target path does not exist: {}", p),
        }
    }
}

impl std::error::Error for FaramirError {}

impl From<io::Error> for FaramirError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound(err.to_string()),
            io::ErrorKind::PermissionDenied => Self::PermissionDenied(err.to_string()),
            _ => Self::IoError(err.to_string()),
        }
    }
}
