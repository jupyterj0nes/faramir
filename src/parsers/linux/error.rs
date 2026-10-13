use std::fmt;

/// Unique error codes for Linux persistence parsing failures
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinuxPersistenceError {
    /// File not found (Code: ERR_LNX_IO_NOT_FOUND, 1001)
    FileNotFound(String),
    /// Permission denied reading file (Code: ERR_LNX_IO_PERMISSION, 1002)
    PermissionDenied(String),
    /// Generic I/O error (Code: ERR_LNX_IO_GENERIC, 1003)
    IoError(String),
    /// Empty or zero-byte file (Code: ERR_LNX_EMPTY_FILE, 1004)
    EmptyFile(String),

    /// Invalid cron format (Code: ERR_LNX_CRON_SYNTAX, 2001)
    InvalidCronSyntax(String),
    /// Missing cron user field (Code: ERR_LNX_CRON_NO_USER, 2002)
    MissingCronUser(String),
    /// Missing cron command field (Code: ERR_LNX_CRON_NO_CMD, 2003)
    MissingCronCommand(String),
    /// Invalid anacron interval/delay (Code: ERR_LNX_ANACRON_INVALID, 2004)
    InvalidAnacronEntry(String),

    /// Systemd missing Unit section (Code: ERR_LNX_SYS_NO_UNIT, 3001)
    SystemdMissingUnitSection(String),
    /// Systemd missing Service/Timer section (Code: ERR_LNX_SYS_NO_EXEC, 3002)
    SystemdMissingExec(String),
    /// Systemd invalid key-value pair (Code: ERR_LNX_SYS_SYNTAX, 3003)
    SystemdSyntaxError(String),
    /// Systemd generator binary not executable (Code: ERR_LNX_SYS_GEN_NOT_EXEC, 3004)
    SystemdGeneratorInvalid(String),

    /// Shell profile missing content (Code: ERR_LNX_SHELL_EMPTY, 4001)
    ShellProfileEmpty(String),
    /// Malformed export or function (Code: ERR_LNX_SHELL_SYNTAX, 4002)
    ShellProfileSyntax(String),

    /// LD_PRELOAD file contains invalid path (Code: ERR_LNX_LDPRELOAD_INVALID, 5001)
    LdPreloadInvalidEntry(String),
    /// LD_PRELOAD missing libraries (Code: ERR_LNX_LDPRELOAD_EMPTY, 5002)
    LdPreloadEmpty(String),

    /// SSH authorized_keys line invalid (Code: ERR_LNX_SSH_KEY_INVALID, 6001)
    SshKeyInvalid(String),
    /// SSH config syntax error (Code: ERR_LNX_SSH_CFG_SYNTAX, 6002)
    SshConfigSyntax(String),

    /// Sudoers syntax invalid (Code: ERR_LNX_SUDO_SYNTAX, 7001)
    SudoersSyntax(String),
    /// Sudoers missing user or rule (Code: ERR_LNX_SUDO_INCOMPLETE, 7002)
    SudoersIncomplete(String),

    /// PAM module syntax error (Code: ERR_LNX_PAM_SYNTAX, 8001)
    PamSyntax(String),
    /// PAM missing control flag (Code: ERR_LNX_PAM_NO_FLAG, 8002)
    PamMissingFlag(String),

    /// Udev rule syntax error (Code: ERR_LNX_UDEV_SYNTAX, 9001)
    UdevSyntax(String),
    /// Udev missing RUN key (Code: ERR_LNX_UDEV_NO_RUN, 9002)
    UdevNoRunAction(String),

    /// Kernel module entry invalid (Code: ERR_LNX_MOD_SYNTAX, 10001)
    KernelModuleSyntax(String),

    /// Package manager hook syntax invalid (Code: ERR_LNX_PKG_SYNTAX, 11001)
    PackageHookSyntax(String),

    /// XDG desktop file missing Exec key (Code: ERR_LNX_XDG_NO_EXEC, 12001)
    XdgMissingExec(String),
    /// XDG desktop syntax error (Code: ERR_LNX_XDG_SYNTAX, 12002)
    XdgSyntax(String),

    /// Proc parsing failed (Code: ERR_LNX_PROC_PARSE, 13001)
    ProcParseError(String),
}

impl LinuxPersistenceError {
    /// Return the textual uppercase error code
    pub fn code(&self) -> &'static str {
        match self {
            Self::FileNotFound(_) => "ERR_LNX_IO_NOT_FOUND",
            Self::PermissionDenied(_) => "ERR_LNX_IO_PERMISSION",
            Self::IoError(_) => "ERR_LNX_IO_GENERIC",
            Self::EmptyFile(_) => "ERR_LNX_EMPTY_FILE",

            Self::InvalidCronSyntax(_) => "ERR_LNX_CRON_SYNTAX",
            Self::MissingCronUser(_) => "ERR_LNX_CRON_NO_USER",
            Self::MissingCronCommand(_) => "ERR_LNX_CRON_NO_CMD",
            Self::InvalidAnacronEntry(_) => "ERR_LNX_ANACRON_INVALID",

            Self::SystemdMissingUnitSection(_) => "ERR_LNX_SYS_NO_UNIT",
            Self::SystemdMissingExec(_) => "ERR_LNX_SYS_NO_EXEC",
            Self::SystemdSyntaxError(_) => "ERR_LNX_SYS_SYNTAX",
            Self::SystemdGeneratorInvalid(_) => "ERR_LNX_SYS_GEN_NOT_EXEC",

            Self::ShellProfileEmpty(_) => "ERR_LNX_SHELL_EMPTY",
            Self::ShellProfileSyntax(_) => "ERR_LNX_SHELL_SYNTAX",

            Self::LdPreloadInvalidEntry(_) => "ERR_LNX_LDPRELOAD_INVALID",
            Self::LdPreloadEmpty(_) => "ERR_LNX_LDPRELOAD_EMPTY",

            Self::SshKeyInvalid(_) => "ERR_LNX_SSH_KEY_INVALID",
            Self::SshConfigSyntax(_) => "ERR_LNX_SSH_CFG_SYNTAX",

            Self::SudoersSyntax(_) => "ERR_LNX_SUDO_SYNTAX",
            Self::SudoersIncomplete(_) => "ERR_LNX_SUDO_INCOMPLETE",

            Self::PamSyntax(_) => "ERR_LNX_PAM_SYNTAX",
            Self::PamMissingFlag(_) => "ERR_LNX_PAM_NO_FLAG",

            Self::UdevSyntax(_) => "ERR_LNX_UDEV_SYNTAX",
            Self::UdevNoRunAction(_) => "ERR_LNX_UDEV_NO_RUN",

            Self::KernelModuleSyntax(_) => "ERR_LNX_MOD_SYNTAX",

            Self::PackageHookSyntax(_) => "ERR_LNX_PKG_SYNTAX",

            Self::XdgMissingExec(_) => "ERR_LNX_XDG_NO_EXEC",
            Self::XdgSyntax(_) => "ERR_LNX_XDG_SYNTAX",

            Self::ProcParseError(_) => "ERR_LNX_PROC_PARSE",
        }
    }

    /// Return unique numeric error identifier
    pub fn error_number(&self) -> u32 {
        match self {
            Self::FileNotFound(_) => 1001,
            Self::PermissionDenied(_) => 1002,
            Self::IoError(_) => 1003,
            Self::EmptyFile(_) => 1004,

            Self::InvalidCronSyntax(_) => 2001,
            Self::MissingCronUser(_) => 2002,
            Self::MissingCronCommand(_) => 2003,
            Self::InvalidAnacronEntry(_) => 2004,

            Self::SystemdMissingUnitSection(_) => 3001,
            Self::SystemdMissingExec(_) => 3002,
            Self::SystemdSyntaxError(_) => 3003,
            Self::SystemdGeneratorInvalid(_) => 3004,

            Self::ShellProfileEmpty(_) => 4001,
            Self::ShellProfileSyntax(_) => 4002,

            Self::LdPreloadInvalidEntry(_) => 5001,
            Self::LdPreloadEmpty(_) => 5002,

            Self::SshKeyInvalid(_) => 6001,
            Self::SshConfigSyntax(_) => 6002,

            Self::SudoersSyntax(_) => 7001,
            Self::SudoersIncomplete(_) => 7002,

            Self::PamSyntax(_) => 8001,
            Self::PamMissingFlag(_) => 8002,

            Self::UdevSyntax(_) => 9001,
            Self::UdevNoRunAction(_) => 9002,

            Self::KernelModuleSyntax(_) => 10001,

            Self::PackageHookSyntax(_) => 11001,

            Self::XdgMissingExec(_) => 12001,
            Self::XdgSyntax(_) => 12002,

            Self::ProcParseError(_) => 13001,
        }
    }
}

impl fmt::Display for LinuxPersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} - {}] ", self.code(), self.error_number())?;
        match self {
            Self::FileNotFound(p) => write!(f, "File not found: {}", p),
            Self::PermissionDenied(p) => write!(f, "Permission denied: {}", p),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::EmptyFile(p) => write!(f, "File is empty: {}", p),

            Self::InvalidCronSyntax(msg) => write!(f, "Invalid cron syntax: {}", msg),
            Self::MissingCronUser(msg) => write!(f, "Missing cron user: {}", msg),
            Self::MissingCronCommand(msg) => write!(f, "Missing cron command: {}", msg),
            Self::InvalidAnacronEntry(msg) => write!(f, "Invalid anacron line: {}", msg),

            Self::SystemdMissingUnitSection(p) => write!(f, "Systemd unit missing section in: {}", p),
            Self::SystemdMissingExec(p) => write!(f, "Systemd unit missing ExecStart/Timer in: {}", p),
            Self::SystemdSyntaxError(msg) => write!(f, "Systemd syntax error: {}", msg),
            Self::SystemdGeneratorInvalid(p) => write!(f, "Invalid systemd generator: {}", p),

            Self::ShellProfileEmpty(p) => write!(f, "Shell profile has no content: {}", p),
            Self::ShellProfileSyntax(msg) => write!(f, "Shell profile syntax issue: {}", msg),

            Self::LdPreloadInvalidEntry(msg) => write!(f, "LD_PRELOAD invalid entry: {}", msg),
            Self::LdPreloadEmpty(p) => write!(f, "LD_PRELOAD file is empty: {}", p),

            Self::SshKeyInvalid(msg) => write!(f, "Invalid SSH authorized key: {}", msg),
            Self::SshConfigSyntax(msg) => write!(f, "SSH config syntax error: {}", msg),

            Self::SudoersSyntax(msg) => write!(f, "Sudoers syntax error: {}", msg),
            Self::SudoersIncomplete(msg) => write!(f, "Sudoers rule incomplete: {}", msg),

            Self::PamSyntax(msg) => write!(f, "PAM rule syntax error: {}", msg),
            Self::PamMissingFlag(msg) => write!(f, "PAM rule missing control flag: {}", msg),

            Self::UdevSyntax(msg) => write!(f, "Udev rule syntax error: {}", msg),
            Self::UdevNoRunAction(msg) => write!(f, "Udev rule has no RUN directive: {}", msg),

            Self::KernelModuleSyntax(msg) => write!(f, "Kernel module definition syntax: {}", msg),

            Self::PackageHookSyntax(msg) => write!(f, "Package manager hook syntax error: {}", msg),

            Self::XdgMissingExec(p) => write!(f, "XDG .desktop file missing Exec key in: {}", p),
            Self::XdgSyntax(msg) => write!(f, "XDG desktop syntax error: {}", msg),

            Self::ProcParseError(msg) => write!(f, "Proc parse failure: {}", msg),
        }
    }
}

impl std::error::Error for LinuxPersistenceError {}

impl From<std::io::Error> for LinuxPersistenceError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::FileNotFound(err.to_string()),
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied(err.to_string()),
            _ => Self::IoError(err.to_string()),
        }
    }
}
