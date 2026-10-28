#!/usr/bin/env bash
# Read-only collection of the persistence surface of a Linux host, in the
# layout UAC produces, so the result can be fed to `faramir -f <tar.gz>`.
#
#   sudo bash linux_collect.sh [outdir]      ->  <outdir>/uac-<host>-linux-<ts>.tar.gz
#
# Nothing on the host is modified. Only configuration is copied: no shell
# histories, no logs, no private keys, no shadow file.
set -u
OUT="${1:-/tmp/faramir-collect}"
HOST="$(hostname -s | tr '[:upper:]' '[:lower:]')"
TS="$(date -u +%Y%m%d%H%M%S)"
PKG="uac-${HOST}-linux-${TS}"
ROOT="$OUT/$PKG/[root]"
LIVE="$OUT/$PKG/live_response/process"
mkdir -p "$ROOT" "$LIVE"

copy() {  # copy <path> keeping the tree, silently skipping what is absent
    local p
    for p in "$@"; do
        [ -e "$p" ] || continue
        if [ -d "$p" ]; then
            mkdir -p "$ROOT$p" && cp -a "$p/." "$ROOT$p/" 2>/dev/null
        else
            mkdir -p "$ROOT$(dirname "$p")" && cp -a "$p" "$ROOT$p" 2>/dev/null
        fi
    done
}

copy /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
copy /var/spool/cron
copy /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /run/systemd/system
copy /etc/systemd/system-generators /lib/systemd/system-generators /usr/lib/systemd/system-generators
copy /etc/rc.local /etc/init.d
copy /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment /etc/zsh
copy /etc/ld.so.preload
copy /etc/ssh/sshd_config /etc/ssh/sshd_config.d
copy /etc/sudoers /etc/sudoers.d
copy /etc/pam.d
copy /etc/udev/rules.d /lib/udev/rules.d /usr/lib/udev/rules.d
copy /etc/modules /etc/modules-load.d /etc/modprobe.d
copy /etc/apt/apt.conf.d
copy /etc/xdg/autostart
copy /etc/passwd /etc/hostname /etc/os-release
for h in /root /home/*; do
    [ -d "$h" ] || continue
    for f in .bashrc .profile .bash_profile .bash_login .zshrc .zprofile .ssh/authorized_keys .ssh/authorized_keys2 .config/autostart; do
        copy "$h/$f"
    done
    copy "$h/.config/systemd/user"
done

# live response: what only a running system can tell
ls -l /proc/[0-9]*/exe 2>/dev/null > "$LIVE/running_processes_full_paths.txt"
ps -eo pid,ppid,user,lstart,cmd > "$LIVE/ps.txt" 2>/dev/null
hostname > "$OUT/$PKG/hostname.txt"
{
    echo "uac read-only collection by scripts/linux_collect.sh"
    echo "host=$HOST date=$TS kernel=$(uname -r)"
} > "$OUT/$PKG/uac.log"

( cd "$OUT" && tar -czf "$PKG.tar.gz" "$PKG" && rm -rf "$PKG" )
sha256sum "$OUT/$PKG.tar.gz"
