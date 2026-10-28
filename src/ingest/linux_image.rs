//! Linux volumes inside disk images: ext2/ext3/ext4 partitions, plain or
//! inside LVM, with the persistence surface copied out into a staging
//! folder laid out like the original root (`etc/`, `home/`, `usr/lib/…`).
//!
//! The partition walk, the ext4 reader and the LVM handling follow masstin's
//! `parse_image_linux`; the differences are a shared reader instead of a raw
//! pointer, logical volumes read in place instead of dumped to a temp file,
//! and XFS, btrfs and LUKS volumes reported rather than passed over quietly.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use ext4_view::{Ext4, Ext4Read};

use crate::errors::FaramirError;
use crate::windows::diag;

/// GPT type GUID of a Linux file system partition (0FC63DAF-8483-4772-8E79-3D69D8477DE4).
pub const GPT_LINUX_FS_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];
/// GPT type GUID of a Linux LVM partition (E6D6D379-F507-44C2-A23C-238F2A3DF928).
pub const GPT_LINUX_LVM_GUID: [u8; 16] = [
    0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28,
];
const EXT_SUPER_MAGIC: u16 = 0xEF53;
/// Largest single file copied out (units, crontabs and keys are tiny; this guards against a stray blob).
pub const MAX_FILE_BYTES: u64 = 16 << 20;
/// Deepest directory recursion below a listed directory.
pub const MAX_DEPTH: usize = 8;
/// Files copied per volume before stopping.
pub const MAX_FILES: usize = 50_000;

// ─── a reader several consumers can share ────────────────────────────────────

/// Clonable handle over one `Read + Seek`, so the NTFS extractor, the VSS
/// walker and the ext4 reader (which wants to own its reader) can all use
/// the same image without copying it. Every call seeks explicitly, so the
/// shared position never leaks between users.
pub struct SharedReader<R> {
    inner: Rc<RefCell<R>>,
    offset: u64,
    pos: u64,
}

impl<R> Clone for SharedReader<R> {
    fn clone(&self) -> Self {
        SharedReader { inner: Rc::clone(&self.inner), offset: self.offset, pos: 0 }
    }
}

impl<R: Read + Seek> SharedReader<R> {
    pub fn new(reader: R) -> Self {
        SharedReader { inner: Rc::new(RefCell::new(reader)), offset: 0, pos: 0 }
    }

    /// A view starting `offset` bytes further in (a partition, a physical volume).
    pub fn at(&self, offset: u64) -> Self {
        SharedReader { inner: Rc::clone(&self.inner), offset: self.offset + offset, pos: 0 }
    }

    /// Absolute read, independent of the cursor.
    pub fn read_at(&self, start: u64, dst: &mut [u8]) -> io::Result<()> {
        let mut r = self.inner.borrow_mut();
        r.seek(SeekFrom::Start(self.offset + start))?;
        r.read_exact(dst)
    }
}

impl<R: Read + Seek> Read for SharedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut r = self.inner.borrow_mut();
        r.seek(SeekFrom::Start(self.offset + self.pos))?;
        let n = r.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SharedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?,
            SeekFrom::End(d) => {
                let end = self.inner.borrow_mut().seek(SeekFrom::End(0))?;
                end.saturating_sub(self.offset).checked_add_signed(d).ok_or_else(|| io::Error::other("seek before start"))?
            }
        };
        Ok(self.pos)
    }
}

impl<R: Read + Seek + 'static> Ext4Read for SharedReader<R> {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.read_at(start_byte, dst).map_err(|e| -> Box<dyn core::error::Error + Send + Sync + 'static> { Box::new(e) })
    }
}

// ─── what is on a volume ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    Ntfs,
    BitLocker,
    Ext,
    Xfs,
    Btrfs,
    F2fs,
    Swap,
    Lvm,
    Luks,
    Fat,
    Unknown,
}

impl VolumeKind {
    pub fn label(&self) -> &'static str {
        match self {
            VolumeKind::Ntfs => "NTFS",
            VolumeKind::BitLocker => "BitLocker",
            VolumeKind::Ext => "ext2/3/4",
            VolumeKind::Xfs => "XFS",
            VolumeKind::Btrfs => "btrfs",
            VolumeKind::F2fs => "F2FS",
            VolumeKind::Swap => "swap",
            VolumeKind::Lvm => "LVM2",
            VolumeKind::Luks => "LUKS",
            VolumeKind::Fat => "FAT",
            VolumeKind::Unknown => "unknown",
        }
    }

    /// Linux file systems Faramir reads today.
    pub fn is_readable_linux(&self) -> bool {
        matches!(self, VolumeKind::Ext)
    }

    /// Linux volumes recognised but not read (reported, never silent).
    pub fn is_unsupported_linux(&self) -> bool {
        matches!(self, VolumeKind::Xfs | VolumeKind::Btrfs | VolumeKind::F2fs)
    }
}

fn bytes_at<R: Read + Seek>(r: &SharedReader<R>, off: u64, n: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; n];
    r.read_at(off, &mut b).ok().map(|_| b)
}

/// Identify a volume by its on-disk signatures.
pub fn sniff<R: Read + Seek>(r: &SharedReader<R>, offset: u64) -> VolumeKind {
    let v = r.at(offset);
    if let Some(b) = bytes_at(&v, 0, 11) {
        if &b[3..11] == b"NTFS    " {
            return VolumeKind::Ntfs;
        }
        if &b[3..11] == b"-FVE-FS-" {
            return VolumeKind::BitLocker;
        }
        if &b[..4] == b"XFSB" {
            return VolumeKind::Xfs;
        }
        if &b[..6] == b"LUKS\xba\xbe" {
            return VolumeKind::Luks;
        }
    }
    if let Some(b) = bytes_at(&v, 0x438, 2) {
        if u16::from_le_bytes([b[0], b[1]]) == EXT_SUPER_MAGIC {
            return VolumeKind::Ext;
        }
    }
    if let Some(b) = bytes_at(&v, 512, 8) {
        if &b == b"LABELONE" {
            return VolumeKind::Lvm;
        }
    }
    if let Some(b) = bytes_at(&v, 0x10040, 8) {
        if &b == b"_BHRfS_M" {
            return VolumeKind::Btrfs;
        }
    }
    if let Some(b) = bytes_at(&v, 0x400, 4) {
        if b == [0x10, 0x20, 0xF5, 0xF2] {
            return VolumeKind::F2fs;
        }
    }
    if let Some(b) = bytes_at(&v, 4096 - 10, 10) {
        if &b == b"SWAPSPACE2" {
            return VolumeKind::Swap;
        }
    }
    if let Some(b) = bytes_at(&v, 0x36, 8) {
        if b.starts_with(b"FAT") {
            return VolumeKind::Fat;
        }
    }
    if let Some(b) = bytes_at(&v, 0x52, 8) {
        if b.starts_with(b"FAT32") {
            return VolumeKind::Fat;
        }
    }
    VolumeKind::Unknown
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub offset: u64,
    pub size: u64,
    pub kind: VolumeKind,
    /// `gpt`, `mbr` or `whole` (no partition table, the image is a volume).
    pub table: &'static str,
}

/// Every partition of the image with what it holds. GPT entries of any type
/// GUID and MBR entries of any type are sniffed; an image with no table is
/// sniffed at offset 0.
pub fn list_volumes<R: Read + Seek>(r: &SharedReader<R>, image_size: u64) -> Vec<Volume> {
    let mut out = Vec::new();
    let Some(mbr) = bytes_at(r, 0, 512) else { return out };
    if mbr[510] == 0x55 && mbr[511] == 0xAA {
        if mbr[446 + 4] == 0xEE {
            if let Some(h) = bytes_at(r, 512, 92) {
                if &h[..8] == b"EFI PART" {
                    let entry_lba = u64::from_le_bytes(h[72..80].try_into().unwrap_or([0; 8]));
                    let count = u32::from_le_bytes(h[80..84].try_into().unwrap_or([0; 4]));
                    let esize = u32::from_le_bytes(h[84..88].try_into().unwrap_or([0; 4])) as u64;
                    for i in 0..count.min(128) as u64 {
                        let Some(e) = bytes_at(r, entry_lba * 512 + i * esize, esize.max(128) as usize) else { break };
                        if e[..16].iter().all(|&b| b == 0) {
                            continue;
                        }
                        let first = u64::from_le_bytes(e[32..40].try_into().unwrap_or([0; 8]));
                        let last = u64::from_le_bytes(e[40..48].try_into().unwrap_or([0; 8]));
                        let offset = first * 512;
                        if offset == 0 || offset >= image_size || last < first {
                            continue;
                        }
                        out.push(Volume { offset, size: (last - first + 1) * 512, kind: sniff(r, offset), table: "gpt" });
                    }
                }
            }
        } else {
            for i in 0..4 {
                let e = &mbr[446 + i * 16..446 + (i + 1) * 16];
                let ptype = e[4];
                let lba = u32::from_le_bytes(e[8..12].try_into().unwrap_or([0; 4])) as u64;
                let sectors = u32::from_le_bytes(e[12..16].try_into().unwrap_or([0; 4])) as u64;
                if ptype == 0 || lba == 0 || lba * 512 >= image_size {
                    continue;
                }
                out.push(Volume { offset: lba * 512, size: sectors * 512, kind: sniff(r, lba * 512), table: "mbr" });
            }
        }
    }
    if out.is_empty() {
        let kind = sniff(r, 0);
        if kind != VolumeKind::Unknown {
            out.push(Volume { offset: 0, size: image_size, kind, table: "whole" });
        }
    }
    out
}

// ─── what to copy out ────────────────────────────────────────────────────────

/// Directories copied recursively.
pub const LINUX_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/etc/systemd/user",
    "/usr/lib/systemd/system",
    "/usr/lib/systemd/user",
    "/lib/systemd/system",
    "/run/systemd/system",
    "/etc/systemd/system-generators",
    "/usr/lib/systemd/system-generators",
    "/lib/systemd/system-generators",
    "/etc/init.d",
    "/etc/profile.d",
    "/etc/zsh",
    "/etc/ssh/sshd_config.d",
    "/etc/sudoers.d",
    "/etc/pam.d",
    "/etc/udev/rules.d",
    "/usr/lib/udev/rules.d",
    "/lib/udev/rules.d",
    "/etc/modules-load.d",
    "/etc/modprobe.d",
    "/etc/apt/apt.conf.d",
    "/etc/xdg/autostart",
];

/// Single files copied when present.
pub const LINUX_FILES: &[&str] = &[
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/rc.local",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/etc/ld.so.preload",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/modules",
    "/etc/passwd",
    "/etc/hostname",
    "/etc/os-release",
];

/// Files looked for in every home directory (and `/root`).
pub const HOME_FILES: &[&str] = &[
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".zshrc",
    ".zprofile",
    ".ssh/authorized_keys",
    ".ssh/authorized_keys2",
];
/// Directories looked for in every home directory.
pub const HOME_DIRS: &[&str] = &[".config/autostart", ".config/systemd/user"];

/// `/lib`, `/bin`, `/sbin` pointing into `/usr` (usr-merge): their contents
/// are reached through `/usr/…`, so the duplicates are not copied.
fn usr_merged(fs: &Ext4, dir: &str) -> bool {
    for top in ["/lib", "/bin", "/sbin", "/lib64"] {
        if dir == top || dir.starts_with(&format!("{top}/")) {
            return fs.symlink_metadata(top).map(|m| m.is_symlink()).unwrap_or(false);
        }
    }
    false
}

/// Progress of one volume's extraction.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Extracted {
    pub files: usize,
    pub bytes: u64,
    pub skipped_large: usize,
    pub errors: usize,
    pub hostname: Option<String>,
}

struct Copier<'a> {
    fs: &'a Ext4,
    out: &'a Path,
    label: &'a str,
    stats: Extracted,
    seen: HashSet<String>,
}

impl Copier<'_> {
    fn dest(&self, linux_path: &str) -> PathBuf {
        self.out.join(linux_path.trim_start_matches('/').replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    fn copy_file(&mut self, linux_path: &str) {
        if self.stats.files >= MAX_FILES || !self.seen.insert(linux_path.to_string()) {
            return;
        }
        let meta = match self.fs.metadata(linux_path) {
            Ok(m) => m,
            Err(_) => return, // absent, or a dangling link: nothing to copy
        };
        if !meta.file_type().is_regular_file() {
            return;
        }
        if meta.len() > MAX_FILE_BYTES {
            self.stats.skipped_large += 1;
            diag::record(FaramirError::LinuxExtractError(format!(
                "{}: {linux_path} is {} bytes, above the {} MB limit",
                self.label,
                meta.len(),
                MAX_FILE_BYTES >> 20
            )));
            return;
        }
        match self.fs.read(linux_path) {
            Ok(data) => {
                let dest = self.dest(linux_path);
                if let Some(p) = dest.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                match std::fs::write(&dest, &data) {
                    Ok(()) => {
                        self.stats.files += 1;
                        self.stats.bytes += data.len() as u64;
                        let secs = meta.modified().seconds();
                        if let Some(t) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs.max(0) as u64)) {
                            let _ = std::fs::File::options().write(true).open(&dest).and_then(|f| f.set_modified(t));
                        }
                    }
                    Err(e) => {
                        self.stats.errors += 1;
                        diag::record(FaramirError::LinuxExtractError(format!("{}: {linux_path} -> {}: {e}", self.label, dest.display())));
                    }
                }
            }
            Err(e) => {
                self.stats.errors += 1;
                diag::record(FaramirError::LinuxExtractError(format!("{}: {linux_path}: {e}", self.label)));
            }
        }
    }

    fn copy_dir(&mut self, linux_dir: &str, depth: usize) {
        if depth > MAX_DEPTH || self.stats.files >= MAX_FILES {
            return;
        }
        let entries = match self.fs.read_dir(linux_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = match entry.file_name().as_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            if name == "." || name == ".." {
                continue;
            }
            let path = format!("{}/{}", linux_dir.trim_end_matches('/'), name);
            // follow links to files (unit `.wants` entries) but not to directories
            let meta = match self.fs.metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                let is_link = self.fs.symlink_metadata(&path).map(|m| m.is_symlink()).unwrap_or(false);
                if !is_link {
                    self.copy_dir(&path, depth + 1);
                }
            } else if meta.file_type().is_regular_file() {
                self.copy_file(&path);
            }
        }
    }
}

/// Copy the persistence surface of an ext file system (at `offset` inside
/// `reader`) under `out_dir`, keeping the original tree.
pub fn extract_from_ext<R: Read + Seek + 'static>(reader: &SharedReader<R>, offset: u64, out_dir: &Path, label: &str) -> Result<Extracted, FaramirError> {
    let fs = Ext4::load(Box::new(reader.at(offset))).map_err(|e| FaramirError::ExtParseError(format!("{label}: {e}")))?;
    extract_from_fs(&fs, out_dir, label)
}

/// Same, for an already-open file system (logical volumes come here).
pub fn extract_from_fs(fs: &Ext4, out_dir: &Path, label: &str) -> Result<Extracted, FaramirError> {
    std::fs::create_dir_all(out_dir).map_err(|e| FaramirError::StagingDirFailed(format!("{}: {e}", out_dir.display())))?;
    let mut c = Copier { fs, out: out_dir, label, stats: Extracted::default(), seen: HashSet::new() };
    for f in LINUX_FILES {
        c.copy_file(f);
    }
    for d in LINUX_DIRS {
        if usr_merged(fs, d) {
            continue;
        }
        c.copy_dir(d, 0);
    }
    let mut homes: Vec<String> = vec!["/root".to_string()];
    if let Ok(entries) = fs.read_dir("/home") {
        for e in entries.flatten() {
            if let Ok(n) = e.file_name().as_str() {
                if n != "." && n != ".." && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    homes.push(format!("/home/{n}"));
                }
            }
        }
    }
    for h in homes {
        for f in HOME_FILES {
            c.copy_file(&format!("{h}/{f}"));
        }
        for d in HOME_DIRS {
            c.copy_dir(&format!("{h}/{d}"), 0);
        }
    }
    c.stats.hostname = fs.read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    Ok(c.stats)
}

// ─── LVM ─────────────────────────────────────────────────────────────────────

/// Linear logical volume read in place: every access re-resolves the
/// extent map through the `lvm2` crate (cheap, no I/O) and reads from the
/// shared image. Striped, mirrored and thin layouts fail at seek time and
/// are reported by the caller.
struct LvReader<R: Read + Seek> {
    lvm: Rc<lvm2::Lvm2>,
    name: String,
    pv: SharedReader<R>,
}

impl<R: Read + Seek + 'static> Ext4Read for LvReader<R> {
    fn read(&mut self, start_byte: u64, dst: &mut [u8]) -> Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        let boxed = |e: String| -> Box<dyn core::error::Error + Send + Sync + 'static> { Box::new(io::Error::other(e)) };
        let mut lv = self.lvm.open_lv_by_name(&self.name, self.pv.clone()).ok_or_else(|| boxed(format!("LV {} vanished", self.name)))?;
        lv.seek(SeekFrom::Start(start_byte)).map_err(|e| boxed(e.to_string()))?;
        lv.read_exact(dst).map_err(|e| boxed(e.to_string()))?;
        Ok(())
    }
}

/// One logical volume of a physical volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalVolume {
    pub vg: String,
    pub name: String,
    pub size: u64,
    pub kind: VolumeKind,
}

/// Open the LVM physical volume at `offset` and describe its logical volumes.
pub fn list_logical_volumes<R: Read + Seek + 'static>(reader: &SharedReader<R>, offset: u64, label: &str) -> Result<(Rc<lvm2::Lvm2>, Vec<LogicalVolume>), FaramirError> {
    let pv = reader.at(offset);
    let lvm = lvm2::Lvm2::open(pv.clone()).map_err(|e| FaramirError::LvmParseError(format!("{label}: {e:?}")))?;
    let lvm = Rc::new(lvm);
    let mut out = Vec::new();
    for lv in lvm.lvs() {
        let size = lv.size_in_extents() * lvm.extent_size();
        let name = lv.name().to_string();
        let kind = match lvm.open_lv_by_name(&name, pv.clone()) {
            Some(mut open) => {
                let mut magic = [0u8; 2];
                let ext = open.seek(SeekFrom::Start(0x438)).is_ok() && open.read_exact(&mut magic).is_ok() && u16::from_le_bytes(magic) == EXT_SUPER_MAGIC;
                if ext {
                    VolumeKind::Ext
                } else {
                    let mut head = [0u8; 4];
                    if open.seek(SeekFrom::Start(0)).is_ok() && open.read_exact(&mut head).is_ok() && &head == b"XFSB" {
                        VolumeKind::Xfs
                    } else {
                        VolumeKind::Unknown
                    }
                }
            }
            None => VolumeKind::Unknown,
        };
        out.push(LogicalVolume { vg: lvm.vg_name().to_string(), name, size, kind });
    }
    Ok((lvm, out))
}

/// Copy the persistence surface of an ext logical volume.
pub fn extract_from_lv<R: Read + Seek + 'static>(reader: &SharedReader<R>, offset: u64, lvm: Rc<lvm2::Lvm2>, lv: &LogicalVolume, out_dir: &Path, label: &str) -> Result<Extracted, FaramirError> {
    let src = LvReader { lvm, name: lv.name.clone(), pv: reader.at(offset) };
    let fs = Ext4::load(Box::new(src)).map_err(|e| {
        let text = e.to_string();
        if text.contains("not linear") || text.contains("stripes") || text.contains("not on this PV") || text.contains("no suitable segment") {
            FaramirError::LvmUnsupportedLayout(format!("{label}: {}/{}: {text}", lv.vg, lv.name))
        } else {
            FaramirError::ExtParseError(format!("{label}: {}/{}: {text}", lv.vg, lv.name))
        }
    })?;
    extract_from_fs(&fs, out_dir, label)
}

/// Staging folder name for a Linux volume; `_linux` is what the CLI keys on.
pub fn linux_dir_name(part_idx: usize, lv: Option<&LogicalVolume>) -> String {
    match lv {
        Some(l) => format!("partition_{part_idx}_lvm_{}_{}_linux", sanitize(&l.vg), sanitize(&l.name)),
        None => format!("partition_{part_idx}_linux"),
    }
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect()
}

/// Is this staging folder a Linux volume written by [`linux_dir_name`]?
pub fn is_linux_volume_dir(name: &str) -> bool {
    name.starts_with("partition_") && name.ends_with("_linux")
}
