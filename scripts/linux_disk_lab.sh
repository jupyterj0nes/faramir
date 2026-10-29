#!/usr/bin/env bash
# Disk images for testing Faramir's Linux volume reader, built on a real host.
#
#   sudo bash linux_disk_lab.sh [outdir]
#
# Produces, in <outdir>:
#   gpt_ext4.img        32 MiB, GPT, one Linux-filesystem partition, ext4,
#                       a small root with one canary per technique
#   mbr_lvm_ext4.img    48 MiB, MBR type 0x8e, one LVM PV, VG "vg_lab",
#                       linear LV "root" with ext4 and the same small root
#   real_ext4.img       256 MiB, no partition table, ext4 holding a read-only
#                       copy of THIS host's persistence surface (what
#                       linux_collect.sh gathers), for a real-data run
#   truth.txt           the canaries and the host name, one per line
#   sha256.txt
#
# Needs loop devices and (for the LVM image) the lvm2 tools; the VG is
# created on a loop device and removed again at the end. Nothing on the
# host's own volumes is changed.
set -u
OUT="${1:-/tmp/faramir-disklab}"
mkdir -p "$OUT"
cd "$OUT" || exit 1
rm -f gpt_ext4.img mbr_lvm_ext4.img gpt_xfs.img mbr_lvm_xfs.img real_ext4.img truth.txt sha256.txt
MNT=/tmp/faramir-disklab-mnt
mkdir -p "$MNT"
: > truth.txt

populate() {  # populate <mountpoint> <tag>
    local m="$1" tag="$2"
    mkdir -p "$m"/etc/cron.d "$m"/etc/systemd/system/multi-user.target.wants "$m"/usr/lib/systemd/system \
        "$m"/etc/sudoers.d "$m"/etc/pam.d "$m"/home/bob/.ssh "$m"/root "$m"/var/spool/cron/crontabs \
        "$m"/etc/profile.d "$m"/etc/udev/rules.d "$m"/etc/modprobe.d "$m"/etc/ssh
    ln -s usr/lib "$m/lib"
    ln -s usr/bin "$m/bin"
    echo "lab-$tag" > "$m/etc/hostname"
    printf 'root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n' > "$m/etc/passwd"
    printf 'PRETTY_NAME="Faramir Lab"\nID=lab\n' > "$m/etc/os-release"
    printf 'SHELL=/bin/sh\n*/5 * * * * root /opt/lab/%s/crontab.sh\n' "$tag" > "$m/etc/crontab"
    printf '@reboot root /opt/lab/%s/cron_d.sh\n' "$tag" > "$m/etc/cron.d/lab"
    printf '0 3 * * * /opt/lab/%s/spool.sh\n' "$tag" > "$m/var/spool/cron/crontabs/bob"
    printf '[Unit]\nDescription=Lab service\n[Service]\nExecStart=/opt/lab/%s/service.sh\n[Install]\nWantedBy=multi-user.target\n' "$tag" > "$m/usr/lib/systemd/system/lab.service"
    ln -s /usr/lib/systemd/system/lab.service "$m/etc/systemd/system/multi-user.target.wants/lab.service"
    printf '[Unit]\nDescription=Lab timer\n[Timer]\nOnBootSec=1min\n[Install]\nWantedBy=timers.target\n' > "$m/etc/systemd/system/lab.timer"
    printf '[Unit]\nDescription=Lab timer job\n[Service]\nExecStart=/opt/lab/%s/timer.sh\n' "$tag" > "$m/etc/systemd/system/lab-timer.service"
    printf 'bob ALL=(ALL) NOPASSWD: /opt/lab/%s/sudo.sh\n' "$tag" > "$m/etc/sudoers.d/lab"
    printf 'auth sufficient pam_permit.so\nauth optional pam_exec.so /opt/lab/%s/pam.sh\n' "$tag" > "$m/etc/pam.d/lab-login"
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForFaramirLab%s lab-%s@faramir\n' "$tag" "$tag" > "$m/home/bob/.ssh/authorized_keys"
    printf 'export PATH=$PATH:/opt/lab/%s\n/opt/lab/%s/bashrc.sh &\n' "$tag" "$tag" > "$m/home/bob/.bashrc"
    printf '/opt/lab/%s/root_profile.sh\n' "$tag" > "$m/root/.profile"
    printf '/opt/lab/%s/preload.so\n' "$tag" > "$m/etc/ld.so.preload"
    printf 'AuthorizedKeysCommand /opt/lab/%s/akc.sh\nAuthorizedKeysCommandUser nobody\n' "$tag" > "$m/etc/ssh/sshd_config"
    printf '/opt/lab/%s/profile_d.sh\n' "$tag" > "$m/etc/profile.d/lab.sh"
    printf 'ACTION=="add", SUBSYSTEM=="usb", RUN+="/opt/lab/%s/udev.sh"\n' "$tag" > "$m/etc/udev/rules.d/99-lab.rules"
    printf 'install lab_mod /opt/lab/%s/modprobe.sh\n' "$tag" > "$m/etc/modprobe.d/lab.conf"
    # files that are deleted again: nothing points to them afterwards
    printf '* * * * * root /opt/lab/%s/deleted_cron.sh\n' "$tag" > "$m/etc/cron.d/gone"
    printf '[Unit]\nDescription=Gone\n[Service]\nExecStart=/opt/lab/%s/deleted_service.sh\n' "$tag" > "$m/etc/systemd/system/gone.service"
    printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeletedKeyForFaramirLab%s deleted-%s@faramir\n' "$tag" "$tag" > "$m/home/bob/.ssh/authorized_keys2"
    sync
    rm -f "$m/etc/cron.d/gone" "$m/etc/systemd/system/gone.service" "$m/home/bob/.ssh/authorized_keys2"
    sync
    # a file replaced the way editors do it (write a new file, rename over): the old inode and its blocks are freed
    printf 'SHELL=/bin/sh\n*/7 * * * * root /opt/lab/%s/crontab_v2.sh\n' "$tag" > "$m/etc/crontab.new"
    mv -f "$m/etc/crontab.new" "$m/etc/crontab"
    sync
    # a file rewritten in place (truncate and write): whether the old blocks survive is up to the allocator
    printf 'bob ALL=(ALL) NOPASSWD: /opt/lab/%s/sudo_v2.sh\n' "$tag" > "$m/etc/sudoers.d/lab"
    sync
    for t in cron_d spool service timer pam bashrc root_profile akc profile_d udev modprobe crontab_v2 sudo_v2; do
        echo "$tag $t /opt/lab/$tag/$t.sh" >> truth.txt
    done
    echo "$tag preload /opt/lab/$tag/preload.so" >> truth.txt
    echo "$tag deleted_cron /opt/lab/$tag/deleted_cron.sh" >> truth.txt
    echo "$tag deleted_service /opt/lab/$tag/deleted_service.sh" >> truth.txt
    echo "$tag deleted_key deleted-$tag@faramir" >> truth.txt
    echo "$tag previous_crontab /opt/lab/$tag/crontab.sh" >> truth.txt
    echo "$tag inplace_sudo /opt/lab/$tag/sudo.sh" >> truth.txt
    echo "$tag hostname lab-$tag" >> truth.txt
    echo "$tag key lab-$tag@faramir" >> truth.txt
}

# --- 1. GPT + ext4 ------------------------------------------------------------
truncate -s 32M gpt_ext4.img
sgdisk -Z -n 1:2048:0 -t 1:8300 -c 1:"lab root" gpt_ext4.img >/dev/null
L=$(losetup --find --show -P gpt_ext4.img)
mkfs.ext4 -q -L labroot "${L}p1"
mount "${L}p1" "$MNT"
populate "$MNT" gpt
umount "$MNT"
losetup -d "$L"

# --- 2. MBR + LVM + ext4 ------------------------------------------------------
truncate -s 48M mbr_lvm_ext4.img
parted -s mbr_lvm_ext4.img mklabel msdos mkpart primary 1MiB 100% set 1 lvm on
L=$(losetup --find --show -P mbr_lvm_ext4.img)
pvcreate -ff -y "${L}p1" >/dev/null
vgcreate vg_lab "${L}p1" >/dev/null
lvcreate -y -L 36M -n root vg_lab >/dev/null
mkfs.ext4 -q -L lvroot /dev/vg_lab/root
mount /dev/vg_lab/root "$MNT"
populate "$MNT" lvm
umount "$MNT"
vgchange -an vg_lab >/dev/null
losetup -d "$L"   # the VG only existed through the loop device; the image keeps its metadata

# --- 2b. GPT + XFS (v5, CRC) ---------------------------------------------------
truncate -s 64M gpt_xfs.img
sgdisk -Z -n 1:2048:0 -t 1:8300 -c 1:"lab xfs" gpt_xfs.img >/dev/null
L=$(losetup --find --show -P gpt_xfs.img)
mkfs.xfs -q -f -L labxfs "${L}p1"
mount "${L}p1" "$MNT"
populate "$MNT" xfs
# a directory too big for the inode's short form, so the leaf/node code paths run
mkdir -p "$MNT/usr/lib/systemd/system/noise.d"
for i in $(seq 1 300); do echo "noise $i" > "$MNT/usr/lib/systemd/system/noise.d/noise_$i.txt"; done
sync
umount "$MNT"
losetup -d "$L"

# --- 2c. MBR + LVM + XFS (what RHEL and its relatives install by default) ------
truncate -s 80M mbr_lvm_xfs.img
parted -s mbr_lvm_xfs.img mklabel msdos mkpart primary 1MiB 100% set 1 lvm on
L=$(losetup --find --show -P mbr_lvm_xfs.img)
pvcreate -ff -y "${L}p1" >/dev/null
vgcreate vg_xfs "${L}p1" >/dev/null
lvcreate -y -L 64M -n root vg_xfs >/dev/null
mkfs.xfs -q -f -L lvxfs /dev/vg_xfs/root
mount /dev/vg_xfs/root "$MNT"
populate "$MNT" lvmxfs
umount "$MNT"
vgchange -an vg_xfs >/dev/null
losetup -d "$L"

# --- 3. this host's real persistence surface on a plain ext4 volume -----------
truncate -s 256M real_ext4.img
mkfs.ext4 -q -L realroot real_ext4.img
L=$(losetup --find --show real_ext4.img)
mount "$L" "$MNT"
copy() {
    local p
    for p in "$@"; do
        [ -e "$p" ] || continue
        if [ -d "$p" ]; then mkdir -p "$MNT$p" && cp -a "$p/." "$MNT$p/" 2>/dev/null
        else mkdir -p "$MNT$(dirname "$p")" && cp -a "$p" "$MNT$p" 2>/dev/null; fi
    done
}
copy /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron
copy /etc/systemd/system /usr/lib/systemd/system /run/systemd/system /etc/systemd/system-generators /usr/lib/systemd/system-generators
copy /etc/rc.local /etc/init.d /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment /etc/zsh /etc/ld.so.preload
copy /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/sudoers /etc/sudoers.d /etc/pam.d /etc/udev/rules.d /usr/lib/udev/rules.d
copy /etc/modules /etc/modules-load.d /etc/modprobe.d /etc/apt/apt.conf.d /etc/xdg/autostart /etc/passwd /etc/hostname /etc/os-release
[ -L /lib ] && ln -s usr/lib "$MNT/lib"
for h in /root /home/*; do
    [ -d "$h" ] || continue
    for f in .bashrc .profile .bash_profile .zshrc .ssh/authorized_keys .config/autostart .config/systemd/user; do copy "$h/$f"; done
done
umount "$MNT"
losetup -d "$L"
echo "real hostname $(hostname -s | tr '[:upper:]' '[:lower:]')" >> truth.txt

rmdir "$MNT" 2>/dev/null
sha256sum gpt_ext4.img mbr_lvm_ext4.img gpt_xfs.img mbr_lvm_xfs.img real_ext4.img truth.txt > sha256.txt
cat sha256.txt
cat truth.txt
