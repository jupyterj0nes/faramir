//! What a stock system ships with: the Autoruns "hide Microsoft entries"
//! idea, offline and for both systems, plus the analyst's own allow-list
//! (`--known-good <faramir csv>` from a clean host, the PersistenceSniper
//! `-DiffCSV` idea).
//!
//! A stock match never cancels a high-level rule: `mshta http://…` is
//! malicious wherever it sits. It only stops a medium or low rule from
//! making the row `candidate` on weak evidence, and it keeps the row in the
//! statistical null, where it belongs.

use std::collections::HashSet;
use std::path::Path;

use super::normalize::{DirFamily, Os, Row};
use crate::errors::FaramirError;

/// A stock entry: technique (empty = any), image name (empty = any) and the
/// folder families it is expected in (empty = any).
struct Stock {
    technique: &'static str,
    image: &'static str,
    families: &'static [DirFamily],
}

const SYS: &[DirFamily] = &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir];
const SYS_BARE: &[DirFamily] = &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir, DirFamily::Bare];

const WINDOWS_STOCK: &[Stock] = &[
    // Run / RunOnce values every Windows ships with
    Stock { technique: "registry_run_key", image: "securityhealthsystray.exe", families: SYS },
    Stock { technique: "registry_run_key", image: "onedrive.exe", families: &[DirFamily::UserLocalAppData, DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "onedrivesetup.exe", families: &[DirFamily::UserLocalAppData, DirFamily::System32, DirFamily::SysWow64] },
    Stock { technique: "registry_run_key", image: "vmtoolsd.exe", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "vboxtray.exe", families: SYS },
    Stock { technique: "registry_run_key", image: "ctfmon.exe", families: SYS },
    Stock { technique: "registry_run_key", image: "msedge.exe", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "chrome.exe", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "igfxtray.exe", families: SYS },
    Stock { technique: "registry_run_key", image: "hkcmd.exe", families: SYS },
    Stock { technique: "registry_run_key", image: "igfxpers.exe", families: SYS },
    Stock { technique: "registry_run_key", image: "rtkngui64.exe", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "ravcpl64.exe", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "wab.exe", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "msteams.exe", families: &[DirFamily::UserLocalAppData, DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "teams.exe", families: &[DirFamily::UserLocalAppData, DirFamily::ProgramFiles] },
    Stock { technique: "registry_run_key", image: "update.exe", families: &[DirFamily::UserLocalAppData] },
    Stock { technique: "registry_runonce_key", image: "rundll32.exe", families: SYS_BARE },
    Stock { technique: "registry_runonce_key", image: "mscoree.dll", families: SYS },
    Stock { technique: "registry_runonce_key", image: "wab.exe", families: &[DirFamily::ProgramFiles] },
    // Winlogon
    Stock { technique: "winlogon_shell_property", image: "explorer.exe", families: &[DirFamily::Bare, DirFamily::WindowsDir] },
    Stock { technique: "winlogon_userinit_property", image: "userinit.exe", families: SYS },
    Stock { technique: "safeboot_alternateshell", image: "cmd.exe", families: SYS_BARE },
    Stock { technique: "boot_execute", image: "autochk", families: &[DirFamily::Bare] },
    Stock { technique: "boot_execute", image: "autocheck", families: &[DirFamily::Bare] },
    Stock { technique: "screensaver", image: "", families: SYS },
    // services and drivers from the system folders
    Stock { technique: "windows_service", image: "svchost.exe", families: SYS },
    Stock { technique: "windows_service", image: "", families: SYS },
    Stock { technique: "servicedll_hijacking", image: "", families: SYS },
    Stock { technique: "scheduled_task", image: "", families: SYS },
    Stock { technique: "scheduled_task__xml_", image: "", families: SYS },
    Stock { technique: "active_setup_stubpath", image: "", families: SYS },
    Stock { technique: "app_paths", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir, DirFamily::ProgramFiles] },
    Stock { technique: "file_association_hijack", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir, DirFamily::ProgramFiles] },
    Stock { technique: "office_add-in", image: "", families: &[DirFamily::ProgramFiles] },
    Stock { technique: "shell_extension___bho", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir, DirFamily::ProgramFiles] },
    Stock { technique: "com_object_hijacking", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir, DirFamily::ProgramFiles] },
    Stock { technique: "com_treatas_redirect", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::WindowsDir, DirFamily::ProgramFiles] },
    Stock { technique: "credential_provider", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::ProgramFiles] },
    Stock { technique: "group_policy_extension_dll", image: "", families: SYS },
    Stock { technique: "time_provider_dll", image: "w32time.dll", families: SYS_BARE },
    Stock { technique: "time_provider_dll", image: "vmictimeprovider.dll", families: SYS_BARE },
    // LSA / SSP packages
    Stock { technique: "lsa_packages", image: "msv1_0", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "kerberos", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "wdigest", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "tspkg", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "pku2u", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "schannel", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "negoexts", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "cloudap", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "scecli", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "rassfm", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "kdcsvc", families: &[DirFamily::Bare] },
    Stock { technique: "lsa_packages", image: "livessp", families: &[DirFamily::Bare] },
    Stock { technique: "security_support_provider", image: "credssp.dll", families: SYS_BARE },
    Stock { technique: "security_support_provider", image: "msapsspc.dll", families: SYS_BARE },
    Stock { technique: "security_support_provider", image: "schannel.dll", families: SYS_BARE },
    Stock { technique: "security_support_provider", image: "msnsspc.dll", families: SYS_BARE },
    Stock { technique: "security_support_provider", image: "digest.dll", families: SYS_BARE },
    Stock { technique: "security_support_provider", image: "pwdssp.dll", families: SYS_BARE },
    Stock { technique: "security_support_provider", image: "credssp", families: &[DirFamily::Bare] },
    Stock { technique: "security_support_provider", image: "msapsspc", families: &[DirFamily::Bare] },
    Stock { technique: "security_support_provider", image: "schannel", families: &[DirFamily::Bare] },
    Stock { technique: "security_support_provider", image: "msnsspc", families: &[DirFamily::Bare] },
    Stock { technique: "security_support_provider", image: "digest", families: &[DirFamily::Bare] },
    Stock { technique: "security_support_provider", image: "pwdssp", families: &[DirFamily::Bare] },
    // network providers
    Stock { technique: "network_provider_dll", image: "ntlanman.dll", families: SYS_BARE },
    Stock { technique: "network_provider_dll", image: "drprov.dll", families: SYS_BARE },
    Stock { technique: "network_provider_dll", image: "davclnt.dll", families: SYS_BARE },
    Stock { technique: "network_provider_dll", image: "vmhgfs.dll", families: SYS_BARE },
    Stock { technique: "network_provider_dll", image: "nwprovau.dll", families: SYS_BARE },
    Stock { technique: "network_provider_dll", image: "ptprov.dll", families: SYS_BARE },
    // print monitors
    Stock { technique: "print_monitor_dll", image: "localspl.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "tcpmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "usbmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "wsdmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "appmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "localmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "pjlmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "lprmon.dll", families: SYS_BARE },
    Stock { technique: "print_monitor_dll", image: "msxpsinc.dll", families: SYS_BARE },
    // netsh helpers
    Stock { technique: "netsh_helper_dll", image: "", families: SYS_BARE },
    // SSODL / misc
    Stock { technique: "shellserviceobjectdelayload", image: "webcheck", families: &[DirFamily::Bare] },
    Stock { technique: "shellserviceobjectdelayload", image: "", families: SYS },
    Stock { technique: "winlogon_notify_dll", image: "", families: SYS },
    Stock { technique: "terminal_server_startup_program", image: "rdpclip", families: &[DirFamily::Bare] },
    Stock { technique: "terminal_server_startup_program", image: "rdpclip.exe", families: SYS_BARE },
    Stock { technique: "startup_folder", image: "desktop.ini", families: &[] },
    Stock { technique: "startup_folder", image: "send to onenote.lnk", families: &[] },
    Stock { technique: "startup_folder", image: "onenote.lnk", families: &[] },
    Stock { technique: "powershell_profile_script", image: "", families: &[DirFamily::System32, DirFamily::SysWow64, DirFamily::ProgramFiles] },
    Stock { technique: "image_file_execution_options", image: "vsjitdebugger.exe", families: &[] },
    Stock { technique: "image_file_execution_options", image: "", families: &[DirFamily::Bare] },
    Stock { technique: "windows_error_reporting_debugger", image: "vsjitdebugger.exe", families: &[] },
    Stock { technique: "aedebug_custom_debugger", image: "vsjitdebugger.exe", families: &[] },
    Stock { technique: "group_policy_script", image: "", families: SYS },
];

/// Linux stock entries, matched on image name (or canonical command for the
/// crontab lines Debian and RHEL ship).
const LINUX_STOCK_IMAGES: &[(&str, &str)] = &[
    // cron.{hourly,daily,weekly,monthly} and cron.d from packages
    ("cron:", "0anacron"),
    ("cron:", "apt-compat"),
    ("cron:", "dpkg"),
    ("cron:", "logrotate"),
    ("cron:", "man-db"),
    ("cron:", "apport"),
    ("cron:", "bsdmainutils"),
    ("cron:", "cracklib-runtime"),
    ("cron:", "exim4-base"),
    ("cron:", "mlocate"),
    ("cron:", "plocate"),
    ("cron:", "locate"),
    ("cron:", "popularity-contest"),
    ("cron:", "sysstat"),
    ("cron:", "update-notifier-common"),
    ("cron:", "ubuntu-advantage-tools"),
    ("cron:", "google-chrome"),
    ("cron:", "aide"),
    ("cron:", "certbot"),
    ("cron:", "passwd"),
    ("cron:", "samba"),
    ("cron:", "debtags"),
    ("cron:", "mdadm"),
    ("cron:", "ntp"),
    ("cron:", "cloud-init"),
    ("cron:", "raid-check"),
    ("cron:", "rhsmd"),
    ("cron:", "mlocate.cron"),
    ("cron:", "0yum-daily.cron"),
    ("cron:", "0yum-hourly.cron"),
    ("cron:", "0hourly"),
    ("cron:", "unattended-upgrades"),
    ("cron:", "e2scrub_all"),
    ("cron:", "php"),
    ("cron:", "fstrim"),
    ("cron:", "sa1"),
    ("cron:", "sa2"),
    ("cron:", "debian-sa1"),
    ("cron:", "debian-sa2"),
    ("cron:", "command"),
    ("cron:", "["),
    ("cron:", "[["),
    ("cron:", "cd"),
    ("cron:", "nice"),
    ("cron:", "ionice"),
    ("cron:", "flock"),
    ("cron:", "chronic"),
    ("cron:", "run-parts"),
    ("cron:", "anacron"),
    ("cron:", "test"),
    ("cron:", "debsums"),
    ("cron:", "clamav-freshclam"),
    ("cron:", "freshclam"),
    ("cron:", "awstats"),
    ("cron:", "zfsutils-linux"),
    ("cron:", "snap"),
    ("cron:", "cinder"),
    ("cron:", "keystone"),
    ("cron:", "rkhunter"),
    ("cron:", "chkrootkit"),
    ("cron:", "lynis"),
    ("cron:", "spamassassin"),
    ("cron:", "ntpdate"),
    ("cron:", "ntpsec"),
    ("cron:", "sysstat-collect"),
    ("cron:", "sysstat-summary"),
    ("cron:", "sendmail"),
    ("cron:", "postfix"),
    ("cron:", "quota"),
    ("cron:", "tmpreaper"),
    ("cron:", "tmpwatch"),
    ("cron:", "prelink"),
    ("cron:", "makewhatis"),
    ("cron:", "rpm"),
    ("cron:", "yum-cron"),
    ("cron:", "dnf-automatic"),
    ("cron:", "atop"),
    ("cron:", "atop-rotate"),
    ("anacron:", "run-parts"),
    ("anacron:", "nice"),
    // apt hooks from packages
    ("apt:", "test"),
    ("apt:", "apt-listchanges"),
    ("apt:", "apt-listbugs"),
    ("apt:", "appstreamcli"),
    ("apt:", "dpkg-preconfigure"),
    ("apt:", "needrestart"),
    ("apt:", "apt-helper"),
    ("apt:", "unattended-upgrade"),
    ("apt:", "unattended-upgrades"),
    ("apt:", "apt-esm-hook"),
    ("apt:", "ua"),
    ("apt:", "pro"),
    ("apt:", "command-not-found"),
    ("apt:", "cnf-update-db"),
    ("apt:", "apt"),
    ("apt:", "etckeeper"),
    ("apt:", "update-motd-updates-available"),
    ("apt:", "apt-config"),
    ("apt:", "apport"),
    ("apt:", "snapd"),
    ("apt:", "gnome-software"),
    ("apt:", "packagekit"),
    ("apt:", "pkcon"),
    ("apt:", "debtags"),
    ("apt:", "dpkg"),
    ("apt:", "sh"),
    ("apt:", "true"),
    ("apt:", "false"),
    ("apt:", "flatpak"),
    ("apt:", "zfs"),
    ("apt:", "zsys"),
    ("apt:", "ldconfig"),
    ("apt:", "update-apt-xapian-index"),
    ("apt:", "apt-xapian-index"),
    ("apt:", "mandb"),
    ("apt:", "systemd-tmpfiles"),
    ("apt:", "pkg-config"),
    ("apt:", "pop-upgrade"),
    // udev helpers
    ("udev:", "systemd-run"),
    ("udev:", "udevadm"),
    ("udev:", "modprobe"),
    ("udev:", "kmod"),
    ("udev:", "alsactl"),
    ("udev:", "hdparm"),
    ("udev:", "ifup"),
    ("udev:", "ifdown"),
    ("udev:", "net.agent"),
    ("udev:", "pcmcia-socket-startup"),
    ("udev:", "pcmcia-check-broken-cis"),
    ("udev:", "hid2hci"),
    ("udev:", "fbdev-blacklist"),
    ("udev:", "vmware-usbarbitrator"),
    ("udev:", "google_nvme_id"),
    ("udev:", "google_oslogin_nss_cache"),
    ("udev:", "zfs"),
    ("udev:", "zed"),
    ("udev:", "mdadm"),
    ("udev:", "lvm"),
    ("udev:", "cryptsetup"),
    ("udev:", "dmsetup"),
    ("udev:", "multipath"),
    ("udev:", "kpartx"),
    ("udev:", "mtp-probe"),
    ("udev:", "usb_modeswitch"),
    ("udev:", "ec2nvme-nsid"),
    ("udev:", "ebsnvme-id"),
    ("udev:", "ec2udev-vbd"),
    ("udev:", "ec2udev-vcpu"),
    ("udev:", "sg_inq"),
    ("udev:", "scsi_id"),
    ("udev:", "ata_id"),
    ("udev:", "cdrom_id"),
    ("udev:", "v4l_id"),
    ("udev:", "dmi_memory_id"),
    ("udev:", "fido_id"),
    ("udev:", "iphone-set-info"),
    ("udev:", "ipod-set-info"),
    ("udev:", "libinput-device-group"),
    ("udev:", "tegra-gpu-boost"),
    ("udev:", "nvidia-sleep.sh"),
    ("udev:", "60-ipath.rules"),
    ("udev:", "hwclock-set"),
    ("udev:", "snapd"),
    // profile.d from packages
    ("shell:", "bash_completion.sh"),
    ("shell:", "apps-bin-path.sh"),
    ("shell:", "cedilla-portuguese.sh"),
    ("shell:", "gawk.sh"),
    ("shell:", "gawk.csh"),
    ("shell:", "vte-2.91.sh"),
    ("shell:", "vte.sh"),
    ("shell:", "im-config_wayland.sh"),
    ("shell:", "xdg_dirs_desktop_session.sh"),
    ("shell:", "01-locale-fix.sh"),
    ("shell:", "z97-byobu.sh"),
    ("shell:", "z99-cloud-locale-test.sh"),
    ("shell:", "z99-cloudinit-warnings.sh"),
    ("shell:", "debuginfod.sh"),
    ("shell:", "debuginfod.csh"),
    ("shell:", "lang.sh"),
    ("shell:", "lang.csh"),
    ("shell:", "which2.sh"),
    ("shell:", "which2.csh"),
    ("shell:", "vim.sh"),
    ("shell:", "vim.csh"),
    ("shell:", "colorls.sh"),
    ("shell:", "colorls.csh"),
    ("shell:", "colorgrep.sh"),
    ("shell:", "colorgrep.csh"),
    ("shell:", "colorxzgrep.sh"),
    ("shell:", "colorzgrep.sh"),
    ("shell:", "less.sh"),
    ("shell:", "less.csh"),
    ("shell:", "flatpak.sh"),
    ("shell:", "gnome-ssh-askpass.sh"),
    ("shell:", "gnome-ssh-askpass.csh"),
    ("shell:", "sh.local"),
    ("shell:", "csh.local"),
    ("shell:", "256term.sh"),
    ("shell:", "256term.csh"),
    ("shell:", "packagekit.sh"),
    ("shell:", "nix.sh"),
    ("shell:", "bash_completion"),
    ("shell:", "lesspipe"),
    ("shell:", "dircolors"),
    ("shell:", "ls"),
    ("shell:", "grep"),
    ("shell:", "fgrep"),
    ("shell:", "egrep"),
    ("shell:", "alert"),
    ("shell:", "umask"),
    ("shell:", "mesg"),
    ("shell:", "tty"),
    ("shell:", "export"),
    ("shell:", "shopt"),
    ("shell:", "setterm"),
    ("shell:", "stty"),
    ("shell:", "ulimit"),
    ("shell:", "unset"),
    ("shell:", "echo"),
    ("shell:", "printf"),
    ("shell:", "eval"),
    ("shell:", "case"),
    ("shell:", "if"),
    ("shell:", "fi"),
    ("shell:", "then"),
    ("shell:", "else"),
    ("shell:", "for"),
    ("shell:", "done"),
    ("shell:", "esac"),
    ("shell:", "source"),
    ("shell:", "."),
    ("shell:", "x-terminal-emulator"),
    ("shell:", "tput"),
    ("shell:", "pathmunge"),
    ("shell:", "uname"),
    ("shell:", "id"),
    ("shell:", "cat"),
    ("shell:", "conda"),
    ("shell:", "nvm"),
    ("shell:", "pyenv"),
    ("shell:", "rbenv"),
    ("shell:", "rvm"),
    ("shell:", "sdk"),
    ("shell:", "cargo"),
    ("shell:", "rustup"),
    ("shell:", "go"),
    ("shell:", "node"),
    ("shell:", "deno"),
    ("shell:", "bun"),
    ("shell:", "fzf"),
    ("shell:", "zoxide"),
    ("shell:", "starship"),
    ("shell:", "direnv"),
    ("shell:", "kubectl"),
    ("shell:", "gcloud"),
    ("shell:", "az"),
    ("shell:", "aws"),
    ("shell:", "oh-my-zsh.sh"),
    ("shell:", "oh-my-bash.sh"),
    ("shell:", "powerline"),
    ("shell:", "neofetch"),
    ("shell:", "screenfetch"),
    ("shell:", "fortune"),
    ("shell:", "cowsay"),
    ("shell:", "keychain"),
    ("shell:", "ssh-agent"),
    ("shell:", "gpg-agent"),
    ("shell:", "byobu"),
    ("shell:", "tmux"),
    ("shell:", "screen"),
    // XDG autostart from packages
    ("xdg:", "at-spi-bus-launcher"),
    ("xdg:", "gnome-keyring-daemon"),
    ("xdg:", "gnome-software"),
    ("xdg:", "gsd-"),
    ("xdg:", "im-launch"),
    ("xdg:", "nm-applet"),
    ("xdg:", "polkit-gnome-authentication-agent-1"),
    ("xdg:", "print-applet"),
    ("xdg:", "snap"),
    ("xdg:", "spice-vdagent"),
    ("xdg:", "start-pulseaudio-x11"),
    ("xdg:", "tracker-miner-fs-3"),
    ("xdg:", "tracker-miner-fs"),
    ("xdg:", "update-notifier"),
    ("xdg:", "user-dirs-update"),
    ("xdg:", "vmware-user-suid-wrapper"),
    ("xdg:", "vmware-user"),
    ("xdg:", "xdg-user-dirs-update"),
    ("xdg:", "xdg-user-dirs-gtk-update"),
    ("xdg:", "xfce4-"),
    ("xdg:", "xfsettingsd"),
    ("xdg:", "xscreensaver"),
    ("xdg:", "light-locker"),
    ("xdg:", "blueman-applet"),
    ("xdg:", "caribou"),
    ("xdg:", "deja-dup-monitor"),
    ("xdg:", "evolution-alarm-notify"),
    ("xdg:", "gnome-shell-overrides-migration.sh"),
    ("xdg:", "ibus-daemon"),
    ("xdg:", "orca-autostart"),
    ("xdg:", "pulseaudio"),
    ("xdg:", "pipewire"),
    ("xdg:", "zeitgeist-datahub"),
    ("xdg:", "org.gnome."),
    ("xdg:", "nautilus"),
    ("xdg:", "geoclue-demo-agent"),
    ("xdg:", "ubuntu-report-collect"),
    ("xdg:", "livepatch-notification"),
    ("xdg:", "gnome-initial-setup-copy-worker"),
    ("xdg:", "gnome-initial-setup-first-login"),
    ("xdg:", "kde"),
    ("xdg:", "plasma"),
    ("xdg:", "klipper"),
    ("xdg:", "kwalletd5"),
    ("xdg:", "baloo_file"),
    ("xdg:", "discord"),
    ("xdg:", "slack"),
    ("xdg:", "spotify"),
    ("xdg:", "dropbox"),
    ("xdg:", "nextcloud"),
    ("xdg:", "insync"),
    ("xdg:", "steam"),
    ("xdg:", "syncthing"),
    ("xdg:", "teams"),
    ("xdg:", "zoom"),
    ("xdg:", "1password"),
    ("xdg:", "keepassxc"),
    ("xdg:", "bitwarden"),
    ("xdg:", "cursor"),
    ("xdg:", "code"),
    ("xdg:", "signal-desktop"),
    ("xdg:", "telegram-desktop"),
    ("xdg:", "flameshot"),
    ("xdg:", "redshift"),
    ("xdg:", "copyq"),
    ("xdg:", "solaar"),
    ("xdg:", "variety"),
    ("xdg:", "conky"),
    ("xdg:", "albert"),
    ("xdg:", "ulauncher"),
    ("xdg:", "barrier"),
    ("xdg:", "synergy"),
    ("xdg:", "input-remapper-autoload"),
    // modules commonly auto-loaded
    ("kernel:", "loop"),
    ("kernel:", "lp"),
    ("kernel:", "rtc"),
    ("kernel:", "vboxguest"),
    ("kernel:", "vboxsf"),
    ("kernel:", "vboxvideo"),
    ("kernel:", "vmw_vsock_vmci_transport"),
    ("kernel:", "vmw_pvscsi"),
    ("kernel:", "vmxnet3"),
    ("kernel:", "virtio_net"),
    ("kernel:", "virtio_blk"),
    ("kernel:", "br_netfilter"),
    ("kernel:", "overlay"),
    ("kernel:", "nf_conntrack"),
    ("kernel:", "ip_vs"),
    ("kernel:", "ip_vs_rr"),
    ("kernel:", "ip_vs_wrr"),
    ("kernel:", "ip_vs_sh"),
    ("kernel:", "ip_tables"),
    ("kernel:", "iptable_nat"),
    ("kernel:", "iptable_filter"),
    ("kernel:", "xt_conntrack"),
    ("kernel:", "nf_nat"),
    ("kernel:", "bridge"),
    ("kernel:", "8021q"),
    ("kernel:", "bonding"),
    ("kernel:", "dummy"),
    ("kernel:", "tun"),
    ("kernel:", "fuse"),
    ("kernel:", "nvidia"),
    ("kernel:", "nvidia-drm"),
    ("kernel:", "nvidia-modeset"),
    ("kernel:", "nvidia-uvm"),
    ("kernel:", "zfs"),
    ("kernel:", "kvm"),
    ("kernel:", "kvm_intel"),
    ("kernel:", "kvm_amd"),
    ("kernel:", "vhost_net"),
    ("kernel:", "uinput"),
    ("kernel:", "snd-aloop"),
    ("kernel:", "v4l2loopback"),
    ("kernel:", "wireguard"),
    ("kernel:", "nbd"),
    ("kernel:", "dm_crypt"),
    ("kernel:", "dm-crypt"),
    ("kernel:", "dm_mod"),
    ("kernel:", "dm-mod"),
    ("kernel:", "sg"),
    ("kernel:", "st"),
    ("kernel:", "sunrpc"),
    ("kernel:", "nfs"),
    ("kernel:", "nfsd"),
    ("kernel:", "lockd"),
    ("kernel:", "rbd"),
    ("kernel:", "ceph"),
    ("kernel:", "iscsi_tcp"),
    ("kernel:", "ib_"),
    ("kernel:", "rdma_"),
    ("kernel:", "msr"),
    ("kernel:", "cpuid"),
    ("kernel:", "coretemp"),
    ("kernel:", "nct6775"),
    ("kernel:", "it87"),
    ("kernel:", "i2c-dev"),
    ("kernel:", "i2c_dev"),
    ("kernel:", "ipmi_devintf"),
    ("kernel:", "ipmi_si"),
    ("kernel:", "ipmi_msghandler"),
    ("kernel:", "acpi_ipmi"),
    ("kernel:", "ppdev"),
    ("kernel:", "parport_pc"),
    ("kernel:", "iTCO_wdt"),
    ("kernel:", "itco_wdt"),
    ("kernel:", "softdog"),
    ("kernel:", "btrfs"),
    ("kernel:", "xfs"),
    ("kernel:", "ext4"),
    ("kernel:", "vfat"),
    ("kernel:", "nls_"),
    ("kernel:", "sctp"),
    ("kernel:", "dccp"),
    ("kernel:", "tipc"),
    ("kernel:", "rds"),
    ("kernel:", "openvswitch"),
    ("kernel:", "geneve"),
    ("kernel:", "vxlan"),
    ("kernel:", "ipip"),
    ("kernel:", "gre"),
    ("kernel:", "ip_gre"),
    ("kernel:", "ip6_tables"),
    ("kernel:", "nft_"),
    ("kernel:", "nf_tables"),
    ("kernel:", "xt_"),
    ("kernel:", "cls_"),
    ("kernel:", "sch_"),
    ("kernel:", "act_"),
    ("kernel:", "ifb"),
    ("kernel:", "veth"),
    ("kernel:", "macvlan"),
    ("kernel:", "ipvlan"),
    ("kernel:", "vcan"),
    ("kernel:", "can"),
    ("kernel:", "usbhid"),
    ("kernel:", "hid_"),
    ("kernel:", "snd_"),
    ("kernel:", "snd-"),
    ("kernel:", "bluetooth"),
    ("kernel:", "btusb"),
    ("kernel:", "uvcvideo"),
    ("kernel:", "ath"),
    ("kernel:", "iwlwifi"),
    ("kernel:", "rtl"),
    ("kernel:", "r8169"),
    ("kernel:", "e1000"),
    ("kernel:", "e1000e"),
    ("kernel:", "igb"),
    ("kernel:", "ixgbe"),
    ("kernel:", "i40e"),
    ("kernel:", "mlx"),
    ("kernel:", "bnx"),
    ("kernel:", "tg3"),
    ("kernel:", "virtio"),
    ("kernel:", "hv_"),
    ("kernel:", "xen"),
    ("kernel:", "gve"),
    ("kernel:", "ena"),
    ("kernel:", "nvme"),
    ("kernel:", "ahci"),
    ("kernel:", "mptspi"),
    ("kernel:", "mpt3sas"),
    ("kernel:", "megaraid_sas"),
    ("kernel:", "hpsa"),
    ("kernel:", "smartpqi"),
    ("kernel:", "vmw_balloon"),
    ("kernel:", "vmwgfx"),
    ("kernel:", "efivarfs"),
    ("kernel:", "efivars"),
    ("kernel:", "configs"),
    ("kernel:", "tpm"),
    ("kernel:", "tpm_tis"),
    ("kernel:", "tpm_crb"),
    ("kernel:", "intel_rapl"),
    ("kernel:", "kvmgt"),
    ("kernel:", "vfio"),
    ("kernel:", "vfio_pci"),
    ("kernel:", "vfio-pci"),
    ("kernel:", "binfmt_misc"),
    ("kernel:", "autofs4"),
    ("kernel:", "cifs"),
    ("kernel:", "9p"),
    ("kernel:", "9pnet_virtio"),
    ("kernel:", "virtiofs"),
    ("kernel:", "squashfs"),
    ("kernel:", "isofs"),
    ("kernel:", "udf"),
    ("kernel:", "exfat"),
    ("kernel:", "ntfs3"),
    ("kernel:", "ntfs"),
    ("kernel:", "hfsplus"),
    ("kernel:", "f2fs"),
    ("kernel:", "nilfs2"),
    ("kernel:", "jfs"),
    ("kernel:", "reiserfs"),
    ("kernel:", "zram"),
    ("kernel:", "zswap"),
    ("kernel:", "lz4"),
    ("kernel:", "zstd"),
    ("kernel:", "crc32"),
    ("kernel:", "crct10dif"),
    ("kernel:", "aesni_intel"),
    ("kernel:", "aes_"),
    ("kernel:", "cryptd"),
    ("kernel:", "crypto_"),
    ("kernel:", "sha"),
    ("kernel:", "ghash"),
    ("kernel:", "algif_"),
    ("kernel:", "af_alg"),
    ("kernel:", "dm_multipath"),
    ("kernel:", "dm-multipath"),
    ("kernel:", "scsi_dh"),
    ("kernel:", "raid"),
    ("kernel:", "md_mod"),
    ("kernel:", "linear"),
    ("kernel:", "multipath"),
    ("kernel:", "drbd"),
    ("kernel:", "target_core_mod"),
    ("kernel:", "iscsi_target_mod"),
    ("kernel:", "ib_iser"),
    ("kernel:", "xt_set"),
    ("kernel:", "ip_set"),
    ("kernel:", "ipt_REJECT"),
    ("kernel:", "ipt_reject"),
    ("kernel:", "nf_reject_ipv4"),
    ("kernel:", "nf_defrag_ipv4"),
    ("kernel:", "ip6table_filter"),
    ("kernel:", "ip6table_nat"),
    ("kernel:", "nf_defrag_ipv6"),
    ("kernel:", "xt_MASQUERADE"),
    ("kernel:", "xt_masquerade"),
    ("kernel:", "xt_addrtype"),
    ("kernel:", "xt_comment"),
    ("kernel:", "xt_mark"),
    ("kernel:", "xt_nat"),
    ("kernel:", "xt_tcpudp"),
    ("kernel:", "xt_multiport"),
    ("kernel:", "xt_state"),
    ("kernel:", "xt_limit"),
    ("kernel:", "xt_owner"),
    ("kernel:", "xt_recent"),
    ("kernel:", "xt_hashlimit"),
    ("kernel:", "xt_physdev"),
    ("kernel:", "xt_statistic"),
    ("kernel:", "xt_cgroup"),
    ("kernel:", "xt_bpf"),
    ("kernel:", "xt_u32"),
    ("kernel:", "xt_string"),
    ("kernel:", "xt_length"),
    ("kernel:", "xt_tcpmss"),
    ("kernel:", "xt_ipvs"),
    ("kernel:", "xt_socket"),
    ("kernel:", "xt_TPROXY"),
    ("kernel:", "xt_tproxy"),
    ("kernel:", "xt_REDIRECT"),
    ("kernel:", "xt_redirect"),
    ("kernel:", "xt_LOG"),
    ("kernel:", "xt_log"),
    ("kernel:", "xt_NFLOG"),
    ("kernel:", "xt_nflog"),
    ("kernel:", "xt_CT"),
    ("kernel:", "xt_ct"),
    ("kernel:", "xt_conntrack"),
    ("kernel:", "xt_connmark"),
    ("kernel:", "xt_connlimit"),
    ("kernel:", "xt_policy"),
    ("kernel:", "xt_esp"),
    ("kernel:", "xt_ah"),
    ("kernel:", "xt_ipcomp"),
    ("kernel:", "xt_sctp"),
    ("kernel:", "xt_dccp"),
    ("kernel:", "xt_rpfilter"),
    ("kernel:", "xt_cluster"),
    ("kernel:", "xt_quota"),
    ("kernel:", "xt_time"),
    ("kernel:", "xt_iprange"),
    ("kernel:", "xt_pkttype"),
    ("kernel:", "xt_helper"),
    ("kernel:", "xt_devgroup"),
    ("kernel:", "xt_dscp"),
    ("kernel:", "xt_ecn"),
    ("kernel:", "xt_mac"),
    ("kernel:", "xt_nfacct"),
    ("kernel:", "xt_realm"),
    ("kernel:", "xt_HL"),
    ("kernel:", "xt_hl"),
    ("kernel:", "xt_DSCP"),
    ("kernel:", "xt_TCPMSS"),
    ("kernel:", "xt_tcpmss"),
    ("kernel:", "xt_SECMARK"),
    ("kernel:", "xt_secmark"),
    ("kernel:", "xt_CONNSECMARK"),
    ("kernel:", "xt_connsecmark"),
    ("kernel:", "xt_AUDIT"),
    ("kernel:", "xt_audit"),
    ("kernel:", "xt_CHECKSUM"),
    ("kernel:", "xt_checksum"),
    ("kernel:", "xt_CLASSIFY"),
    ("kernel:", "xt_classify"),
    ("kernel:", "xt_IDLETIMER"),
    ("kernel:", "xt_idletimer"),
    ("kernel:", "xt_LED"),
    ("kernel:", "xt_led"),
    ("kernel:", "xt_NETMAP"),
    ("kernel:", "xt_netmap"),
    ("kernel:", "xt_NFQUEUE"),
    ("kernel:", "xt_nfqueue"),
    ("kernel:", "xt_RATEEST"),
    ("kernel:", "xt_rateest"),
    ("kernel:", "xt_TEE"),
    ("kernel:", "xt_tee"),
    ("kernel:", "xt_TRACE"),
    ("kernel:", "xt_trace"),
    ("kernel:", "xt_cpu"),
];

const LINUX_STOCK_CANON_SUBSTRINGS: &[&str] = &[
    "run-parts --report /etc/cron.hourly",
    "run-parts --report /etc/cron.daily",
    "run-parts --report /etc/cron.weekly",
    "run-parts --report /etc/cron.monthly",
    "test -x /usr/sbin/anacron",
    "root all=(all) all",
    "root all=(all:all) all",
    "%sudo all=(all:all) all",
    "%sudo all=(all) all",
    "%admin all=(all) all",
    "%wheel all=(all) all",
    "%wheel all=(all:all) all",
    "%google-sudoers all=(all:all) nopasswd:all",
    "%google-sudoers all=(all) nopasswd:all",
    "ubuntu all=(all) nopasswd:all",
    "ec2-user all=(all) nopasswd: all",
    "ec2-user all=(all) nopasswd:all",
    "admin all=(all) nopasswd:all",
    "vagrant all=(all) nopasswd: all",
    "vagrant all=(all) nopasswd:all",
    "centos all=(all) nopasswd: all",
    "centos all=(all) nopasswd:all",
    "rocky all=(all) nopasswd: all",
    "almalinux all=(all) nopasswd: all",
    "debian all=(all) nopasswd: all",
    "cloud-user all=(all) nopasswd: all",
    "opc all=(all) nopasswd: all",
    "azureuser all=(all) nopasswd:all",
    "fedora all=(all) nopasswd: all",
    "defaults env_reset",
    "defaults mail_badpass",
    "defaults secure_path=",
    "defaults use_pty",
    "defaults !visiblepw",
    "defaults always_set_home",
    "defaults match_group_by_gid",
    "defaults always_query_group_plugin",
    "defaults env_keep += \"colors displ",
    "defaults env_keep += \"mail ps1 ps2",
    "defaults env_keep += \"lc_",
    "defaults env_keep += \"lang",
    "defaults env_keep += \"ls_colors",
    "defaults env_keep += \"home",
    "defaults requiretty",
    "defaults !requiretty",
    "defaults logfile=/var/log/sudo",
    "defaults lecture=",
    "defaults passwd_tries",
    "defaults timestamp_timeout=",
    "defaults insults",
    "defaults pwfeedback",
    "defaults editor=",
    "defaults umask",
    "defaults use_pty",
    "defaults log_",
    "defaults:",
];

/// Why a row counts as stock, or none.
pub fn stock_reason(row: &Row) -> Option<&'static str> {
    match row.os {
        Os::Windows => {
            for s in WINDOWS_STOCK {
                if !s.technique.is_empty() && s.technique != row.technique {
                    continue;
                }
                if !s.image.is_empty() && s.image != row.image_name {
                    continue;
                }
                if !s.families.is_empty() && !s.families.contains(&row.family) {
                    continue;
                }
                return Some("stock Windows entry");
            }
            None
        }
        Os::Linux => {
            let canon_cmd = row.canon.split_once('|').map(|x| x.1).unwrap_or("");
            if LINUX_STOCK_CANON_SUBSTRINGS.iter().any(|s| canon_cmd.contains(s)) {
                return Some("stock Linux entry");
            }
            let name = row.image_name.as_str();
            for (prefix, image) in LINUX_STOCK_IMAGES {
                if !row.technique.starts_with(prefix) {
                    continue;
                }
                let hit = if image.ends_with('_') || image.ends_with('-') || image.ends_with('.') { name.starts_with(image) } else { name == *image };
                if hit && (row.family.is_system() || row.family == DirFamily::Etc || row.family == DirFamily::Bare || row.technique.starts_with("kernel:") || row.technique.starts_with("shell:") || row.technique.starts_with("xdg:")) {
                    return Some("stock Linux entry");
                }
            }
            // systemd units and timers from the package tree, running package binaries
            if row.technique.starts_with("systemd:") && row.family.is_system() && !row.location.contains("/etc/systemd/") && !row.location.contains("/.config/") {
                return Some("packaged systemd unit");
            }
            // periodic cron scripts and generators whose file lives in the package tree
            if matches!(row.technique.as_str(), "systemd:generator") && row.family.is_system() {
                return Some("packaged generator");
            }
            None
        }
        Os::Unknown => None,
    }
}

/// Entries something vouches for by identity: the clean reference hosts built
/// into the binary (`clean/windows.csv`, `clean/linux.csv`, what the lab's
/// stock Server 2016 and Ubuntu 22.04 hosts carried, measured by
/// `scripts/measure_clean.py`) and the analyst's own faramir CSVs from clean
/// hosts (`--known-good`). An entry here is `habitual` whatever its rules say:
/// a clean machine has it, so every reading of it is benign. The rules keep
/// their clause, add no points and give no state. (The stock pattern list
/// above is weaker: it is opinion, and a high rule overrides it.)
#[derive(Debug, Default, Clone)]
pub struct KnownGood {
    /// From the analyst's CSVs.
    canons: HashSet<String>,
    /// From the clean reference hosts.
    reference: HashSet<String>,
    pub files: usize,
    pub rows: usize,
    pub reference_rows: usize,
}

/// What the clean reference hosts were (the `REFERENCE_*` of `measured.rs`
/// describe the same collections).
pub const REFERENCE_REASON: &str = "on the clean reference hosts";
pub const CSV_REASON: &str = "in known-good CSV";

impl KnownGood {
    pub fn is_empty(&self) -> bool {
        self.canons.is_empty() && self.reference.is_empty()
    }

    pub fn contains(&self, row: &Row) -> bool {
        self.reason(row).is_some()
    }

    /// Why the entry is vouched for, when it is.
    pub fn reason(&self, row: &Row) -> Option<&'static str> {
        // the analyst's own CSV speaks first, the built-in reference after it
        if self.canons.contains(&row.canon) {
            Some(CSV_REASON)
        } else if self.reference.contains(&row.canon) {
            Some(REFERENCE_REASON)
        } else {
            None
        }
    }

    pub fn insert_canon(&mut self, canon: String) {
        self.canons.insert(canon);
    }

    /// Adds the clean reference hosts built into the binary.
    pub fn with_reference(mut self) -> Self {
        let mut errors = Vec::new();
        for (name, text) in [("clean/windows.csv", include_str!("clean/windows.csv")), ("clean/linux.csv", include_str!("clean/linux.csv"))] {
            let rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_reader(text.as_bytes());
            let mut set = HashSet::new();
            self.reference_rows += Self::read(name, rdr, &mut set, &mut errors);
            self.reference.extend(set);
        }
        debug_assert!(errors.is_empty(), "{errors:?}");
        self
    }

    /// Load every file; problems are returned, never fatal.
    pub fn load(paths: &[impl AsRef<Path>]) -> (KnownGood, Vec<FaramirError>) {
        let mut kg = KnownGood::default();
        let mut errors = Vec::new();
        for p in paths {
            let p = p.as_ref();
            let rdr = match csv::ReaderBuilder::new().has_headers(true).flexible(true).from_path(p) {
                Ok(r) => r,
                Err(e) => {
                    errors.push(FaramirError::HuntKnownGoodOpenFailed(format!("{}: {e}", p.display())));
                    continue;
                }
            };
            let mut set = HashSet::new();
            let n = Self::read(&p.display().to_string(), rdr, &mut set, &mut errors);
            kg.canons.extend(set);
            kg.files += 1;
            kg.rows += n;
            errors.push(FaramirError::HuntKnownGoodLoaded(format!("{}: {n} row(s)", p.display())));
        }
        (kg, errors)
    }

    /// Reads one faramir CSV (masstin's names, or the ten-column names of
    /// faramir 0.3 / caarea, or just `event_type,detail`) into a set of
    /// identities. Returns the rows read.
    fn read<R: std::io::Read>(name: &str, mut rdr: csv::Reader<R>, into: &mut HashSet<String>, errors: &mut Vec<FaramirError>) -> usize {
        {
            let p = name;
            let headers = rdr.headers().cloned().unwrap_or_default();
            // masstin's names (what faramir writes now) or the ten-column names of faramir 0.3 / caarea
            let col = |names: &[&str]| headers.iter().position(|h| names.iter().any(|n| h.trim().trim_matches('"').eq_ignore_ascii_case(n)));
            let (Some(ci_art), Some(ci_cmd)) = (col(&["event_type", "artifact"]), col(&["detail", "commandline"])) else {
                errors.push(FaramirError::HuntKnownGoodOpenFailed(format!("{}: no event_type/detail (or artifact/commandline) columns", p)));
                return 0;
            };
            let ci_host = col(&["dst_computer", "computer"]);
            let ci_parent = col(&["source_file", "log_filename", "parentprocessname"]);
            let ci_user = col(&["target_user_name", "target_username"]);
            let mut n = 0usize;
            for (i, rec) in rdr.records().enumerate() {
                let rec = match rec {
                    Ok(r) => r,
                    Err(e) => {
                        errors.push(FaramirError::HuntKnownGoodRowSkipped(format!("{} row {}: {e}", p, i + 2)));
                        continue;
                    }
                };
                let Some(artifact) = rec.get(ci_art) else { continue };
                let cmd = rec.get(ci_cmd).unwrap_or("");
                let e = crate::event::Event {
                    timestamp: String::new(),
                    computer: ci_host.and_then(|c| rec.get(c)).unwrap_or("").to_string(),
                    artifact: artifact.to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: String::new(),
                    target_username: ci_user.and_then(|c| rec.get(c)).unwrap_or("").to_string(),
                    processname: String::new(),
                    commandline: Some(cmd.to_string()),
                    source_file: ci_parent.and_then(|c| rec.get(c)).unwrap_or("").to_string(),
                };
                let row = super::normalize::normalize(0, &e);
                into.insert(row.canon);
                n += 1;
            }
            n
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::hunt::normalize::normalize;

    fn row(artifact: &str, cmd: &str, location: &str) -> Row {
        let e = Event {
            timestamp: String::new(),
            computer: "H".into(),
            artifact: artifact.into(),
            event_id: 0,
            pid: 0,
            subject_username: "User".into(),
            target_username: "User".into(),
            processname: String::new(),
            commandline: Some(cmd.into()),
            source_file: location.into(),
        };
        normalize(0, &e)
    }

    #[test]
    fn windows_stock() {
        assert!(stock_reason(&row("windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:registry_run_key", "\"C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\OneDrive.exe", "")).is_none());
        assert!(stock_reason(&row("windows:persistence:windows_service", "C:\\Windows\\system32\\svchost.exe -k netsvcs", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:windows_service", "\"C:\\Program Files\\Vendor\\svc.exe\"", "")).is_none());
        assert!(stock_reason(&row("windows:persistence:lsa_packages", "msv1_0", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:lsa_packages", "evilssp", "")).is_none());
        assert!(stock_reason(&row("windows:persistence:winlogon_shell_property", "explorer.exe", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:print_monitor_dll", "localspl.dll", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:print_monitor_dll", "C:\\ProgramData\\mon.dll", "")).is_none());
        assert!(stock_reason(&row("windows:persistence:netsh_helper_dll", "ifmon.dll", "")).is_some());
        assert!(stock_reason(&row("windows:persistence:netsh_helper_dll", "C:\\Users\\Public\\h.dll", "")).is_none());
    }

    #[test]
    fn linux_stock() {
        assert!(stock_reason(&row("linux:cron:system_job", "System Cron: cd / && run-parts --report /etc/cron.hourly (File: /etc/crontab)", "crond")).is_some());
        assert!(stock_reason(&row("linux:cron:periodic:daily", "Periodic Cron Script: /etc/cron.daily/apt-compat", "crond")).is_some());
        assert!(stock_reason(&row("linux:cron:periodic:daily", "Periodic Cron Script: /etc/cron.daily/backdoor", "crond")).is_none());
        assert!(stock_reason(&row("linux:systemd:service", "Systemd Unit: ssh.service (Desc: x, Exec: /usr/sbin/sshd -D)", "/lib/systemd/system/ssh.service")).is_some());
        assert!(stock_reason(&row("linux:systemd:service", "Systemd Unit: ssh.service (Desc: x, Exec: /usr/sbin/sshd -D)", "/etc/systemd/system/ssh.service")).is_none());
        assert!(stock_reason(&row("linux:systemd:service", "Systemd Unit: x.service (Desc: x, Exec: /opt/x)", "/lib/systemd/system/x.service")).is_none());
        assert!(stock_reason(&row("linux:sudoers:nopasswd", "Sudoers [/etc/sudoers.d/google line 1]: %google-sudoers ALL=(ALL:ALL) NOPASSWD:ALL", "")).is_some());
        assert!(stock_reason(&row("linux:sudoers:nopasswd", "Sudoers [/etc/sudoers line 1]: bob ALL=(ALL) NOPASSWD:ALL", "")).is_none());
        assert!(stock_reason(&row("linux:sudoers:defaults_override", "Sudoers Defaults [/etc/sudoers line 1]: Defaults env_reset", "")).is_some());
        assert!(stock_reason(&row("linux:apt:package_hook", "APT Hook [/etc/apt/apt.conf.d/20listchanges line 1]: DPkg::Post-Invoke { \"/usr/bin/apt-listchanges --apt\"; };", "")).is_some());
        assert!(stock_reason(&row("linux:kernel:module_load", "Kernel Auto-load Module: br_netfilter (File: /etc/modules-load.d/k8s.conf)", "")).is_some());
        assert!(stock_reason(&row("linux:kernel:module_load", "Kernel Auto-load Module: diamorphine (File: /etc/modules)", "")).is_none());
        assert!(stock_reason(&row("linux:shell:profile_d", "/etc/profile.d/bash_completion.sh [line 3]: . /usr/share/bash-completion/bash_completion", "")).is_some());
    }

    #[test]
    fn known_good_csv_roundtrip() {
        let dir = std::env::temp_dir().join(format!("faramir_kg_{}_{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("clean.csv");
        std::fs::write(
            &p,
            "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"pid\",\"subject_username\",\"target_username\",\"processname\",\"commandline\",\"parentprocessname\"\n\
             \"2026-01-01 00:00:00.000\",\"CLEAN\",\"windows:persistence:registry_run_key\",0,0,\"User\",\"User\",\"agent.exe\",\"C:\\Users\\alice\\AppData\\Roaming\\Corp\\agent.exe\",\"HKCU\\...\\Run\"\n\
             bad row\n",
        )
        .unwrap();
        let (kg, errs) = KnownGood::load(&[&p]);
        assert_eq!(kg.files, 1);
        assert!(kg.rows >= 1);
        assert!(errs.iter().any(|e| e.error_number() == 7005));
        // the same entry on another host for another user matches
        let r = row("windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\Corp\\agent.exe", "");
        assert!(kg.contains(&r));
        let r = row("windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\Corp\\other.exe", "");
        assert!(!kg.contains(&r));
        let (kg2, errs2) = KnownGood::load(&[dir.join("missing.csv")]);
        assert!(kg2.is_empty());
        assert!(errs2.iter().any(|e| e.error_number() == 7003));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
