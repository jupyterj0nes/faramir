use std::fmt;
use std::io;

/// Severity attached to every [`FaramirError`].
///
/// * `Error`   – the artifact could not be processed at all.
/// * `Warning` – processing continued in degraded mode (e.g. dirty hive without logs).
/// * `Info`    – diagnostic only, nothing was lost (e.g. a companion file was skipped).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARN",
            Self::Info => "INFO",
        }
    }
}

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
    /// VMware VMDK descriptor / extent cannot be opened (2015)
    VmdkOpenFailed(String),
    /// Microsoft VHD / VHDX cannot be opened (2016)
    VhdOpenFailed(String),
    /// Secondary image segment (.E02, -s002.vmdk, .002) skipped; its first segment carries it (2017)
    ImageSegmentSkipped(String),
    /// Image is incomplete: descriptor without data file, truncated stream, missing parent (2018)
    ImageIncomplete(String),
    /// Carving: the image or file could not be opened for a raw scan (2019)
    CarveOpenFailed(String),
    /// Carving: a block could not be read; the scan skipped past it (2020)
    CarveReadError(String),
    /// Carving: a read stalled past the time budget; the reader was reopened and the window skipped (2021)
    CarveReadStalled(String),
    /// Carving: a `regf` signature whose base block failed validation (2022)
    CarveHeaderRejected(String),
    /// Carving: the hive bin chain broke before the declared size; the valid prefix was kept (2023)
    CarveHiveTruncated(String),
    /// Carving: valid base block but no usable bins / root cell; nothing carved (2024)
    CarveHiveRejected(String),
    /// Carving: identical to a hive already carved from this image (2025)
    CarveDuplicate(String),
    /// Carving: identical to a hive extracted from the file system or a shadow copy (2026)
    CarveMatchesExtracted(String),
    /// Carving: the carved hive could not be written to the staging folder (2027)
    CarveWriteFailed(String),
    /// Carving: `--carve` was given but nothing carvable was provided (2028)
    CarveNoTarget(String),
    /// Carving: a hive was recovered from raw bytes (2029)
    CarveHiveRecovered(String),
    /// Carving: the scan was abandoned (too many consecutive failures, empty source) (2030)
    CarveAborted(String),
    /// Linux file system (ext2/3/4) could not be opened (2031)
    ExtParseError(String),
    /// LVM physical volume could not be parsed (2032)
    LvmParseError(String),
    /// LVM logical volume uses a layout that is not read (striped, mirrored, thin, RAID, multi-PV) (2033)
    LvmUnsupportedLayout(String),
    /// A Linux volume of a kind that is not read yet (XFS, btrfs, F2FS, swap) (2034)
    LinuxFsUnsupported(String),
    /// LUKS-encrypted volume; nothing can be read without the key (2035)
    LuksEncrypted(String),
    /// A file could not be copied out of a Linux volume; the rest went on (2036)
    LinuxExtractError(String),
    /// Linux volume found and its persistence surface staged (2037)
    LinuxVolumeExtracted(String),
    /// ext4 metadata or jbd2 journal could not be parsed for recovery (2038)
    ExtJournalParseError(String),
    /// The journal held no block copies worth anything (empty, wiped, external) (2039)
    ExtJournalEmpty(String),
    /// A deleted file or a previous version was recovered from an ext volume (2040)
    ExtDeletedRecovered(String),
    /// A deleted file was named but its blocks are reused; no content (2041)
    ExtDeletedContentReused(String),
    /// XFS volume could not be mounted or walked (2042)
    XfsParseError(String),

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
    /// Hive file does not start with the "regf" signature (3019)
    HiveSignatureInvalid(String),
    /// Hive file is shorter than a base block (3020)
    HiveHeaderTruncated(String),
    /// Hive base block XOR-32 checksum mismatch (3021)
    HiveChecksumInvalid(String),
    /// Hive kind cannot be resolved from file name nor header (3022)
    HiveKindUnresolved(String),
    /// File name suggests one hive kind, header another; header wins (3023)
    HiveNameHeaderMismatch(String),
    /// nt_hive2 panicked while parsing a hive (3024)
    HiveParsePanic(String),
    /// Registry companion file (.blf/.regtrans-ms/.LOG*/.TMP/.SAV) ignored as non-hive (3025)
    HiveCompanionSkipped(String),
    /// Same hive path discovered twice (3026)
    HiveDuplicateSkipped(String),
    /// Header says this file is a transaction log, not a primary hive (3027)
    HiveNotPrimaryFile(String),
    /// Dirty hive, but no .LOG1/.LOG2 located under the evidence root (3028)
    TxLogNotFound(String),
    /// Transaction log located but could not be opened or read (3029)
    TxLogOpenFailed(String),
    /// Transaction log lacks the "regf" signature (3030)
    TxLogSignatureInvalid(String),
    /// Transaction log uses the legacy (file type 1/2) format that cannot be replayed (3031)
    TxLogLegacyFormat(String),
    /// Transaction log truncated: an entry claims more bytes than the file has (3032)
    TxLogTruncated(String),
    /// Transaction log entry is structurally invalid (3033)
    TxLogEntryInvalid(String),
    /// Transaction log contains no HvLE entries (3034)
    TxLogNoEntries(String),
    /// Transaction log entries do not continue the hive's sequence number (3035)
    TxLogSequenceMismatch(String),
    /// Transaction log base block belongs to a different hive (3036)
    TxLogHiveMismatch(String),
    /// nt_hive2 rejected the transaction log while attaching it (3037)
    TxLogApplyFailed(String),
    /// nt_hive2 panicked while parsing or applying the transaction log (3038)
    TxLogApplyPanic(String),
    /// Several transaction log candidates scored equally (3039)
    TxLogAmbiguous(String),
    /// Only a prefix of the transaction log entries could be used (3040)
    TxLogPartiallyApplied(String),
    /// SYSTEM hive has no ControlSetNNN key (3041)
    ControlSetNotFound(String),
    /// Technique found no hive of the required kind (3042)
    TechniqueNoApplicableHive(String),
    /// Technique panicked on a hive and that hive was skipped (3043)
    TechniquePanicked(String),
    /// Filesystem walk error during hive discovery (3044)
    HiveDiscoveryIoError(String),
    /// Registry value present but empty (3045)
    ValueEmpty(String),
    /// Hive file is zero bytes (3046)
    HiveEmptyFile(String),
    /// Transaction log was found far from its hive; applied after header verification (3047)
    TxLogRemoteMatch(String),
    /// Dirty hive was rebuilt from transaction logs (3048)
    HiveRecovered(String),
    /// Browser profile or policy JSON could not be parsed (3049)
    BrowserProfileParseError(String),

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
    /// Identical Linux finding seen twice (usr-merged `/lib` and `/usr/lib`, duplicated collection) (4022)
    LinuxDuplicateSkipped(String),

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
            Self::VmdkOpenFailed(_) => "ERR_ING_VMDK_OPEN",
            Self::VhdOpenFailed(_) => "ERR_ING_VHD_OPEN",
            Self::ImageSegmentSkipped(_) => "ERR_ING_IMAGE_SEGMENT_SKIPPED",
            Self::ImageIncomplete(_) => "ERR_ING_IMAGE_INCOMPLETE",
            Self::CarveOpenFailed(_) => "ERR_ING_CARVE_OPEN",
            Self::CarveReadError(_) => "ERR_ING_CARVE_READ",
            Self::CarveReadStalled(_) => "ERR_ING_CARVE_STALLED",
            Self::CarveHeaderRejected(_) => "ERR_ING_CARVE_HEADER_REJECTED",
            Self::CarveHiveTruncated(_) => "ERR_ING_CARVE_HIVE_TRUNCATED",
            Self::CarveHiveRejected(_) => "ERR_ING_CARVE_HIVE_REJECTED",
            Self::CarveDuplicate(_) => "ERR_ING_CARVE_DUPLICATE",
            Self::CarveMatchesExtracted(_) => "ERR_ING_CARVE_MATCHES_EXTRACTED",
            Self::CarveWriteFailed(_) => "ERR_ING_CARVE_WRITE",
            Self::CarveNoTarget(_) => "ERR_ING_CARVE_NO_TARGET",
            Self::CarveHiveRecovered(_) => "ERR_ING_CARVE_HIVE_RECOVERED",
            Self::CarveAborted(_) => "ERR_ING_CARVE_ABORTED",
            Self::ExtParseError(_) => "ERR_ING_EXT_PARSE",
            Self::LvmParseError(_) => "ERR_ING_LVM_PARSE",
            Self::LvmUnsupportedLayout(_) => "ERR_ING_LVM_UNSUPPORTED_LAYOUT",
            Self::LinuxFsUnsupported(_) => "ERR_ING_LINUX_FS_UNSUPPORTED",
            Self::LuksEncrypted(_) => "ERR_ING_LUKS_ENCRYPTED",
            Self::LinuxExtractError(_) => "ERR_ING_LINUX_EXTRACT",
            Self::LinuxVolumeExtracted(_) => "ERR_ING_LINUX_VOLUME_EXTRACTED",
            Self::ExtJournalParseError(_) => "ERR_ING_EXT_JOURNAL_PARSE",
            Self::ExtJournalEmpty(_) => "ERR_ING_EXT_JOURNAL_EMPTY",
            Self::ExtDeletedRecovered(_) => "ERR_ING_EXT_DELETED_RECOVERED",
            Self::ExtDeletedContentReused(_) => "ERR_ING_EXT_DELETED_CONTENT_REUSED",
            Self::XfsParseError(_) => "ERR_ING_XFS_PARSE",

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
            Self::HiveSignatureInvalid(_) => "ERR_WIN_HIVE_SIGNATURE",
            Self::HiveHeaderTruncated(_) => "ERR_WIN_HIVE_TRUNCATED",
            Self::HiveChecksumInvalid(_) => "ERR_WIN_HIVE_CHECKSUM",
            Self::HiveKindUnresolved(_) => "ERR_WIN_HIVE_KIND_UNRESOLVED",
            Self::HiveNameHeaderMismatch(_) => "ERR_WIN_HIVE_NAME_HEADER_MISMATCH",
            Self::HiveParsePanic(_) => "ERR_WIN_HIVE_PARSE_PANIC",
            Self::HiveCompanionSkipped(_) => "ERR_WIN_HIVE_COMPANION_SKIPPED",
            Self::HiveDuplicateSkipped(_) => "ERR_WIN_HIVE_DUPLICATE",
            Self::HiveNotPrimaryFile(_) => "ERR_WIN_HIVE_NOT_PRIMARY",
            Self::TxLogNotFound(_) => "ERR_WIN_TX_LOG_NOT_FOUND",
            Self::TxLogOpenFailed(_) => "ERR_WIN_TX_LOG_OPEN",
            Self::TxLogSignatureInvalid(_) => "ERR_WIN_TX_LOG_SIGNATURE",
            Self::TxLogLegacyFormat(_) => "ERR_WIN_TX_LOG_LEGACY",
            Self::TxLogTruncated(_) => "ERR_WIN_TX_LOG_TRUNCATED",
            Self::TxLogEntryInvalid(_) => "ERR_WIN_TX_LOG_ENTRY_INVALID",
            Self::TxLogNoEntries(_) => "ERR_WIN_TX_LOG_EMPTY",
            Self::TxLogSequenceMismatch(_) => "ERR_WIN_TX_LOG_SEQUENCE",
            Self::TxLogHiveMismatch(_) => "ERR_WIN_TX_LOG_HIVE_MISMATCH",
            Self::TxLogApplyFailed(_) => "ERR_WIN_TX_LOG_APPLY",
            Self::TxLogApplyPanic(_) => "ERR_WIN_TX_LOG_APPLY_PANIC",
            Self::TxLogAmbiguous(_) => "ERR_WIN_TX_LOG_AMBIGUOUS",
            Self::TxLogPartiallyApplied(_) => "ERR_WIN_TX_LOG_PARTIAL",
            Self::ControlSetNotFound(_) => "ERR_WIN_CONTROL_SET_MISSING",
            Self::TechniqueNoApplicableHive(_) => "ERR_WIN_TECH_NO_HIVE",
            Self::TechniquePanicked(_) => "ERR_WIN_TECH_PANIC",
            Self::HiveDiscoveryIoError(_) => "ERR_WIN_HIVE_DISCOVERY_IO",
            Self::ValueEmpty(_) => "ERR_WIN_VALUE_EMPTY",
            Self::HiveEmptyFile(_) => "ERR_WIN_HIVE_EMPTY",
            Self::TxLogRemoteMatch(_) => "ERR_WIN_TX_LOG_REMOTE_MATCH",
            Self::HiveRecovered(_) => "ERR_WIN_HIVE_RECOVERED",
            Self::BrowserProfileParseError(_) => "ERR_WIN_BROWSER_PROFILE_PARSE",

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
            Self::LinuxDuplicateSkipped(_) => "ERR_LNX_DUPLICATE_SKIPPED",

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
            Self::VmdkOpenFailed(_) => 2015,
            Self::VhdOpenFailed(_) => 2016,
            Self::ImageSegmentSkipped(_) => 2017,
            Self::ImageIncomplete(_) => 2018,
            Self::CarveOpenFailed(_) => 2019,
            Self::CarveReadError(_) => 2020,
            Self::CarveReadStalled(_) => 2021,
            Self::CarveHeaderRejected(_) => 2022,
            Self::CarveHiveTruncated(_) => 2023,
            Self::CarveHiveRejected(_) => 2024,
            Self::CarveDuplicate(_) => 2025,
            Self::CarveMatchesExtracted(_) => 2026,
            Self::CarveWriteFailed(_) => 2027,
            Self::CarveNoTarget(_) => 2028,
            Self::CarveHiveRecovered(_) => 2029,
            Self::CarveAborted(_) => 2030,
            Self::ExtParseError(_) => 2031,
            Self::LvmParseError(_) => 2032,
            Self::LvmUnsupportedLayout(_) => 2033,
            Self::LinuxFsUnsupported(_) => 2034,
            Self::LuksEncrypted(_) => 2035,
            Self::LinuxExtractError(_) => 2036,
            Self::LinuxVolumeExtracted(_) => 2037,
            Self::ExtJournalParseError(_) => 2038,
            Self::ExtJournalEmpty(_) => 2039,
            Self::ExtDeletedRecovered(_) => 2040,
            Self::ExtDeletedContentReused(_) => 2041,
            Self::XfsParseError(_) => 2042,

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
            Self::HiveSignatureInvalid(_) => 3019,
            Self::HiveHeaderTruncated(_) => 3020,
            Self::HiveChecksumInvalid(_) => 3021,
            Self::HiveKindUnresolved(_) => 3022,
            Self::HiveNameHeaderMismatch(_) => 3023,
            Self::HiveParsePanic(_) => 3024,
            Self::HiveCompanionSkipped(_) => 3025,
            Self::HiveDuplicateSkipped(_) => 3026,
            Self::HiveNotPrimaryFile(_) => 3027,
            Self::TxLogNotFound(_) => 3028,
            Self::TxLogOpenFailed(_) => 3029,
            Self::TxLogSignatureInvalid(_) => 3030,
            Self::TxLogLegacyFormat(_) => 3031,
            Self::TxLogTruncated(_) => 3032,
            Self::TxLogEntryInvalid(_) => 3033,
            Self::TxLogNoEntries(_) => 3034,
            Self::TxLogSequenceMismatch(_) => 3035,
            Self::TxLogHiveMismatch(_) => 3036,
            Self::TxLogApplyFailed(_) => 3037,
            Self::TxLogApplyPanic(_) => 3038,
            Self::TxLogAmbiguous(_) => 3039,
            Self::TxLogPartiallyApplied(_) => 3040,
            Self::ControlSetNotFound(_) => 3041,
            Self::TechniqueNoApplicableHive(_) => 3042,
            Self::TechniquePanicked(_) => 3043,
            Self::HiveDiscoveryIoError(_) => 3044,
            Self::ValueEmpty(_) => 3045,
            Self::HiveEmptyFile(_) => 3046,
            Self::TxLogRemoteMatch(_) => 3047,
            Self::HiveRecovered(_) => 3048,
            Self::BrowserProfileParseError(_) => 3049,

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
            Self::LinuxDuplicateSkipped(_) => 4022,

            Self::OutFileCreateFailed(_) => 5001,
            Self::OutCsvWriteError(_) => 5002,
            Self::OutCsvFlushFailed(_) => 5003,
            Self::OutDirCreateFailed(_) => 5004,

            Self::CliNoTarget(_) => 6001,
            Self::CliInvalidAction(_) => 6002,
            Self::CliPathNotFound(_) => 6003,
        }
    }

    /// Severity of the condition. Everything is an `Error` unless listed here.
    pub fn severity(&self) -> Severity {
        match self {
            Self::HiveDirtyNoLogs(_)
            | Self::TxLogReplayFailed(_)
            | Self::HiveChecksumInvalid(_)
            | Self::HiveKindUnresolved(_)
            | Self::HiveNameHeaderMismatch(_)
            | Self::TxLogNotFound(_)
            | Self::TxLogLegacyFormat(_)
            | Self::TxLogTruncated(_)
            | Self::TxLogEntryInvalid(_)
            | Self::TxLogNoEntries(_)
            | Self::TxLogSequenceMismatch(_)
            | Self::TxLogApplyFailed(_)
            | Self::TxLogApplyPanic(_)
            | Self::TxLogAmbiguous(_)
            | Self::TxLogPartiallyApplied(_)
            | Self::ControlSetNotFound(_)
            | Self::TechniquePanicked(_)
            | Self::HiveDiscoveryIoError(_)
            | Self::CarveReadError(_)
            | Self::CarveReadStalled(_)
            | Self::CarveHiveTruncated(_)
            | Self::CarveHiveRejected(_)
            | Self::CarveNoTarget(_)
            | Self::LvmUnsupportedLayout(_)
            | Self::LinuxFsUnsupported(_)
            | Self::LuksEncrypted(_)
            | Self::LinuxExtractError(_)
            | Self::ExtJournalParseError(_)
            | Self::ExtDeletedContentReused(_)
            | Self::BrowserProfileParseError(_)
            | Self::ValueEmpty(_) => Severity::Warning,

            Self::HiveCompanionSkipped(_)
            | Self::HiveDuplicateSkipped(_)
            | Self::ImageSegmentSkipped(_)
            | Self::CarveHeaderRejected(_)
            | Self::CarveDuplicate(_)
            | Self::CarveMatchesExtracted(_)
            | Self::CarveHiveRecovered(_)
            | Self::LinuxVolumeExtracted(_)
            | Self::ExtJournalEmpty(_)
            | Self::ExtDeletedRecovered(_)
            | Self::LinuxDuplicateSkipped(_)
            | Self::TxLogHiveMismatch(_)
            | Self::TechniqueNoApplicableHive(_)
            | Self::TxLogRemoteMatch(_)
            | Self::HiveRecovered(_) => Severity::Info,

            _ => Severity::Error,
        }
    }

    /// Subsystem derived from the numeric range.
    pub fn category(&self) -> &'static str {
        match self.error_number() / 1000 {
            1 => "SYS",
            2 => "ING",
            3 => "WIN",
            4 => "LNX",
            5 => "OUT",
            6 => "CLI",
            _ => "UNK",
        }
    }

    /// The free-text detail attached to the error.
    pub fn detail(&self) -> &str {
        match self {
            Self::IoError(s)
            | Self::NotFound(s)
            | Self::PermissionDenied(s)
            | Self::EmptyFile(s)
            | Self::ImageOpenFailed(s)
            | Self::EwfInitFailed(s)
            | Self::NoNtfsPartition(s)
            | Self::BitLockerEncrypted(s)
            | Self::NtfsParseError(s)
            | Self::NtfsUpcaseError(s)
            | Self::NtfsRootDirError(s)
            | Self::NtfsPathNotFound(s)
            | Self::NtfsDataStreamError(s)
            | Self::ArchiveOpenFailed(s)
            | Self::ArchiveCorrupt(s)
            | Self::ArchiveUnpackError(s)
            | Self::StagingDirFailed(s)
            | Self::VssParseError(s)
            | Self::VmdkOpenFailed(s)
            | Self::VhdOpenFailed(s)
            | Self::ImageSegmentSkipped(s)
            | Self::ImageIncomplete(s)
            | Self::CarveOpenFailed(s)
            | Self::CarveReadError(s)
            | Self::CarveReadStalled(s)
            | Self::CarveHeaderRejected(s)
            | Self::CarveHiveTruncated(s)
            | Self::CarveHiveRejected(s)
            | Self::CarveDuplicate(s)
            | Self::CarveMatchesExtracted(s)
            | Self::CarveWriteFailed(s)
            | Self::CarveNoTarget(s)
            | Self::CarveHiveRecovered(s)
            | Self::CarveAborted(s)
            | Self::ExtParseError(s)
            | Self::LvmParseError(s)
            | Self::LvmUnsupportedLayout(s)
            | Self::LinuxFsUnsupported(s)
            | Self::LuksEncrypted(s)
            | Self::LinuxExtractError(s)
            | Self::LinuxVolumeExtracted(s)
            | Self::ExtJournalParseError(s)
            | Self::ExtJournalEmpty(s)
            | Self::ExtDeletedRecovered(s)
            | Self::ExtDeletedContentReused(s)
            | Self::XfsParseError(s)
            | Self::HiveOpenFailed(s)
            | Self::HiveCorrupt(s)
            | Self::HiveDirtyNoLogs(s)
            | Self::TxLogReplayFailed(s)
            | Self::HiveRootKeyFailed(s)
            | Self::KeyNotFound(s)
            | Self::SubkeysEnumFailed(s)
            | Self::ValueNotFound(s)
            | Self::ValueTypeMismatch(s)
            | Self::CurrentControlSetFailed(s)
            | Self::TaskXmlParseError(s)
            | Self::TaskXmlMissingExec(s)
            | Self::TerminalJsonParseError(s)
            | Self::StartupDirReadError(s)
            | Self::PrintMonitorsFailed(s)
            | Self::TimeProvidersFailed(s)
            | Self::NetshFailed(s)
            | Self::PowerShellProfileError(s)
            | Self::HiveSignatureInvalid(s)
            | Self::HiveHeaderTruncated(s)
            | Self::HiveChecksumInvalid(s)
            | Self::HiveKindUnresolved(s)
            | Self::HiveNameHeaderMismatch(s)
            | Self::HiveParsePanic(s)
            | Self::HiveCompanionSkipped(s)
            | Self::HiveDuplicateSkipped(s)
            | Self::HiveNotPrimaryFile(s)
            | Self::TxLogNotFound(s)
            | Self::TxLogOpenFailed(s)
            | Self::TxLogSignatureInvalid(s)
            | Self::TxLogLegacyFormat(s)
            | Self::TxLogTruncated(s)
            | Self::TxLogEntryInvalid(s)
            | Self::TxLogNoEntries(s)
            | Self::TxLogSequenceMismatch(s)
            | Self::TxLogHiveMismatch(s)
            | Self::TxLogApplyFailed(s)
            | Self::TxLogApplyPanic(s)
            | Self::TxLogAmbiguous(s)
            | Self::TxLogPartiallyApplied(s)
            | Self::ControlSetNotFound(s)
            | Self::TechniqueNoApplicableHive(s)
            | Self::TechniquePanicked(s)
            | Self::HiveDiscoveryIoError(s)
            | Self::ValueEmpty(s)
            | Self::HiveEmptyFile(s)
            | Self::TxLogRemoteMatch(s)
            | Self::HiveRecovered(s)
            | Self::BrowserProfileParseError(s)
            | Self::CronSyntax(s)
            | Self::CronNoUser(s)
            | Self::CronNoCommand(s)
            | Self::AnacronSyntax(s)
            | Self::SystemdNoSection(s)
            | Self::SystemdNoExec(s)
            | Self::SystemdSyntax(s)
            | Self::SystemdGeneratorError(s)
            | Self::ShellProfileSyntax(s)
            | Self::LdPreloadInvalid(s)
            | Self::LdPreloadEmpty(s)
            | Self::SshKeyInvalid(s)
            | Self::SshConfigSyntax(s)
            | Self::SudoersSyntax(s)
            | Self::PamSyntax(s)
            | Self::UdevSyntax(s)
            | Self::KernelModuleSyntax(s)
            | Self::PackageHookSyntax(s)
            | Self::XdgNoExec(s)
            | Self::XdgSyntax(s)
            | Self::ProcParseError(s)
            | Self::LinuxDuplicateSkipped(s)
            | Self::OutFileCreateFailed(s)
            | Self::OutCsvWriteError(s)
            | Self::OutCsvFlushFailed(s)
            | Self::OutDirCreateFailed(s)
            | Self::CliNoTarget(s)
            | Self::CliInvalidAction(s)
            | Self::CliPathNotFound(s) => s,
        }
    }

    /// One instance of every variant (with an empty detail). Used by tests to
    /// prove that codes and numbers are unique and that every variant is wired.
    pub fn catalog() -> Vec<FaramirError> {
        let e = String::new;
        vec![
            Self::IoError(e()),
            Self::NotFound(e()),
            Self::PermissionDenied(e()),
            Self::EmptyFile(e()),
            Self::ImageOpenFailed(e()),
            Self::EwfInitFailed(e()),
            Self::NoNtfsPartition(e()),
            Self::BitLockerEncrypted(e()),
            Self::NtfsParseError(e()),
            Self::NtfsUpcaseError(e()),
            Self::NtfsRootDirError(e()),
            Self::NtfsPathNotFound(e()),
            Self::NtfsDataStreamError(e()),
            Self::ArchiveOpenFailed(e()),
            Self::ArchiveCorrupt(e()),
            Self::ArchiveUnpackError(e()),
            Self::StagingDirFailed(e()),
            Self::VssParseError(e()),
            Self::VmdkOpenFailed(e()),
            Self::VhdOpenFailed(e()),
            Self::ImageSegmentSkipped(e()),
            Self::ImageIncomplete(e()),
            Self::CarveOpenFailed(e()),
            Self::CarveReadError(e()),
            Self::CarveReadStalled(e()),
            Self::CarveHeaderRejected(e()),
            Self::CarveHiveTruncated(e()),
            Self::CarveHiveRejected(e()),
            Self::CarveDuplicate(e()),
            Self::CarveMatchesExtracted(e()),
            Self::CarveWriteFailed(e()),
            Self::CarveNoTarget(e()),
            Self::CarveHiveRecovered(e()),
            Self::CarveAborted(e()),
            Self::ExtParseError(e()),
            Self::LvmParseError(e()),
            Self::LvmUnsupportedLayout(e()),
            Self::LinuxFsUnsupported(e()),
            Self::LuksEncrypted(e()),
            Self::LinuxExtractError(e()),
            Self::LinuxVolumeExtracted(e()),
            Self::ExtJournalParseError(e()),
            Self::ExtJournalEmpty(e()),
            Self::ExtDeletedRecovered(e()),
            Self::ExtDeletedContentReused(e()),
            Self::XfsParseError(e()),
            Self::HiveOpenFailed(e()),
            Self::HiveCorrupt(e()),
            Self::HiveDirtyNoLogs(e()),
            Self::TxLogReplayFailed(e()),
            Self::HiveRootKeyFailed(e()),
            Self::KeyNotFound(e()),
            Self::SubkeysEnumFailed(e()),
            Self::ValueNotFound(e()),
            Self::ValueTypeMismatch(e()),
            Self::CurrentControlSetFailed(e()),
            Self::TaskXmlParseError(e()),
            Self::TaskXmlMissingExec(e()),
            Self::TerminalJsonParseError(e()),
            Self::StartupDirReadError(e()),
            Self::PrintMonitorsFailed(e()),
            Self::TimeProvidersFailed(e()),
            Self::NetshFailed(e()),
            Self::PowerShellProfileError(e()),
            Self::HiveSignatureInvalid(e()),
            Self::HiveHeaderTruncated(e()),
            Self::HiveChecksumInvalid(e()),
            Self::HiveKindUnresolved(e()),
            Self::HiveNameHeaderMismatch(e()),
            Self::HiveParsePanic(e()),
            Self::HiveCompanionSkipped(e()),
            Self::HiveDuplicateSkipped(e()),
            Self::HiveNotPrimaryFile(e()),
            Self::TxLogNotFound(e()),
            Self::TxLogOpenFailed(e()),
            Self::TxLogSignatureInvalid(e()),
            Self::TxLogLegacyFormat(e()),
            Self::TxLogTruncated(e()),
            Self::TxLogEntryInvalid(e()),
            Self::TxLogNoEntries(e()),
            Self::TxLogSequenceMismatch(e()),
            Self::TxLogHiveMismatch(e()),
            Self::TxLogApplyFailed(e()),
            Self::TxLogApplyPanic(e()),
            Self::TxLogAmbiguous(e()),
            Self::TxLogPartiallyApplied(e()),
            Self::ControlSetNotFound(e()),
            Self::TechniqueNoApplicableHive(e()),
            Self::TechniquePanicked(e()),
            Self::HiveDiscoveryIoError(e()),
            Self::ValueEmpty(e()),
            Self::HiveEmptyFile(e()),
            Self::TxLogRemoteMatch(e()),
            Self::HiveRecovered(e()),
            Self::BrowserProfileParseError(e()),
            Self::CronSyntax(e()),
            Self::CronNoUser(e()),
            Self::CronNoCommand(e()),
            Self::AnacronSyntax(e()),
            Self::SystemdNoSection(e()),
            Self::SystemdNoExec(e()),
            Self::SystemdSyntax(e()),
            Self::SystemdGeneratorError(e()),
            Self::ShellProfileSyntax(e()),
            Self::LdPreloadInvalid(e()),
            Self::LdPreloadEmpty(e()),
            Self::SshKeyInvalid(e()),
            Self::SshConfigSyntax(e()),
            Self::SudoersSyntax(e()),
            Self::PamSyntax(e()),
            Self::UdevSyntax(e()),
            Self::KernelModuleSyntax(e()),
            Self::PackageHookSyntax(e()),
            Self::XdgNoExec(e()),
            Self::XdgSyntax(e()),
            Self::ProcParseError(e()),
            Self::LinuxDuplicateSkipped(e()),
            Self::OutFileCreateFailed(e()),
            Self::OutCsvWriteError(e()),
            Self::OutCsvFlushFailed(e()),
            Self::OutDirCreateFailed(e()),
            Self::CliNoTarget(e()),
            Self::CliInvalidAction(e()),
            Self::CliPathNotFound(e()),
        ]
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
            Self::VmdkOpenFailed(e) => write!(f, "Cannot open VMDK: {}", e),
            Self::VhdOpenFailed(e) => write!(f, "Cannot open VHD/VHDX: {}", e),
            Self::ImageSegmentSkipped(p) => write!(f, "Secondary image segment skipped (read through its first segment): {}", p),
            Self::ImageIncomplete(e) => write!(f, "Image is incomplete: {}", e),
            Self::CarveOpenFailed(e) => write!(f, "Cannot open source for carving: {}", e),
            Self::CarveReadError(e) => write!(f, "Carving read error, block skipped: {}", e),
            Self::CarveReadStalled(e) => write!(f, "Carving read stalled, reader reopened and window skipped: {}", e),
            Self::CarveHeaderRejected(e) => write!(f, "regf signature rejected: {}", e),
            Self::CarveHiveTruncated(e) => write!(f, "Carved hive is truncated, valid prefix kept: {}", e),
            Self::CarveHiveRejected(e) => write!(f, "Carved hive rejected: {}", e),
            Self::CarveDuplicate(e) => write!(f, "Carved hive is a duplicate of one already carved: {}", e),
            Self::CarveMatchesExtracted(e) => write!(f, "Carved hive is identical to an extracted hive, skipped: {}", e),
            Self::CarveWriteFailed(e) => write!(f, "Cannot write carved hive: {}", e),
            Self::CarveNoTarget(e) => write!(f, "--carve given but nothing to carve: {}", e),
            Self::CarveHiveRecovered(e) => write!(f, "Hive carved from raw bytes: {}", e),
            Self::CarveAborted(e) => write!(f, "Carving abandoned: {}", e),
            Self::ExtParseError(e) => write!(f, "Cannot open ext2/ext3/ext4 file system: {}", e),
            Self::LvmParseError(e) => write!(f, "Cannot parse LVM physical volume: {}", e),
            Self::LvmUnsupportedLayout(e) => write!(f, "LVM logical volume layout not supported (only linear, single PV): {}", e),
            Self::LinuxFsUnsupported(e) => write!(f, "Linux volume of a kind not read yet: {}", e),
            Self::LuksEncrypted(e) => write!(f, "LUKS-encrypted volume skipped: {}", e),
            Self::LinuxExtractError(e) => write!(f, "Could not copy a file out of the Linux volume: {}", e),
            Self::LinuxVolumeExtracted(e) => write!(f, "Linux volume staged: {}", e),
            Self::ExtJournalParseError(e) => write!(f, "ext4 journal recovery not possible: {}", e),
            Self::ExtJournalEmpty(e) => write!(f, "ext4 journal held nothing to recover: {}", e),
            Self::ExtDeletedRecovered(e) => write!(f, "Recovered from ext4 journal: {}", e),
            Self::ExtDeletedContentReused(e) => write!(f, "Deleted file named but its blocks are reused, no content: {}", e),
            Self::XfsParseError(e) => write!(f, "Cannot read XFS volume: {}", e),

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
            Self::HiveSignatureInvalid(p) => write!(f, "File lacks the 'regf' hive signature: {}", p),
            Self::HiveHeaderTruncated(p) => write!(f, "Hive shorter than its 4096-byte base block: {}", p),
            Self::HiveChecksumInvalid(p) => write!(f, "Hive base block checksum mismatch: {}", p),
            Self::HiveKindUnresolved(p) => write!(f, "Cannot tell which hive this is (name and header inconclusive), trying every root: {}", p),
            Self::HiveNameHeaderMismatch(p) => write!(f, "File name and embedded header disagree on hive kind, header wins: {}", p),
            Self::HiveParsePanic(p) => write!(f, "Hive parser panicked, hive skipped: {}", p),
            Self::HiveCompanionSkipped(p) => write!(f, "Registry companion file ignored (not a primary hive): {}", p),
            Self::HiveDuplicateSkipped(p) => write!(f, "Hive already queued, duplicate skipped: {}", p),
            Self::HiveNotPrimaryFile(p) => write!(f, "File is a transaction log, not a primary hive: {}", p),
            Self::TxLogNotFound(p) => write!(f, "Dirty hive but no .LOG1/.LOG2 could be located for: {}", p),
            Self::TxLogOpenFailed(p) => write!(f, "Transaction log cannot be opened: {}", p),
            Self::TxLogSignatureInvalid(p) => write!(f, "Transaction log lacks the 'regf' signature: {}", p),
            Self::TxLogLegacyFormat(p) => write!(f, "Transaction log is in legacy (pre-8.1) format and cannot be replayed: {}", p),
            Self::TxLogTruncated(p) => write!(f, "Transaction log truncated: {}", p),
            Self::TxLogEntryInvalid(p) => write!(f, "Transaction log entry invalid: {}", p),
            Self::TxLogNoEntries(p) => write!(f, "Transaction log has no HvLE entries: {}", p),
            Self::TxLogSequenceMismatch(p) => write!(f, "Transaction log sequence does not follow the hive: {}", p),
            Self::TxLogHiveMismatch(p) => write!(f, "Transaction log belongs to a different hive: {}", p),
            Self::TxLogApplyFailed(p) => write!(f, "Transaction log rejected by parser: {}", p),
            Self::TxLogApplyPanic(p) => write!(f, "Transaction log parser panicked: {}", p),
            Self::TxLogAmbiguous(p) => write!(f, "Several transaction log candidates match equally well: {}", p),
            Self::TxLogPartiallyApplied(p) => write!(f, "Only a prefix of the transaction log was usable: {}", p),
            Self::ControlSetNotFound(p) => write!(f, "No ControlSetNNN key in SYSTEM hive: {}", p),
            Self::TechniqueNoApplicableHive(p) => write!(f, "No hive of the required kind for technique: {}", p),
            Self::TechniquePanicked(p) => write!(f, "Technique panicked on hive and was skipped: {}", p),
            Self::HiveDiscoveryIoError(p) => write!(f, "Filesystem error while discovering hives: {}", p),
            Self::ValueEmpty(p) => write!(f, "Registry value is empty: {}", p),
            Self::HiveEmptyFile(p) => write!(f, "Hive file is zero bytes: {}", p),
            Self::TxLogRemoteMatch(p) => write!(f, "Transaction log found outside the hive folder, matched by header: {}", p),
            Self::HiveRecovered(p) => write!(f, "Dirty hive rebuilt from transaction logs: {}", p),
            Self::BrowserProfileParseError(e) => write!(f, "Cannot parse browser profile or policy file: {}", e),

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
            Self::LinuxDuplicateSkipped(e) => write!(f, "Duplicate Linux finding skipped: {}", e),

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
