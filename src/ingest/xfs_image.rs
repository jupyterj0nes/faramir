//! XFS volumes inside disk images: the file system RHEL, Rocky, Alma and
//! Oracle Linux install by default, as a partition or as an LVM logical
//! volume. Read through the `rust-fs-xfs` driver over any block device that
//! answers positioned reads; the persistence surface comes out as the same
//! root tree the ext4 path produces, so the Linux techniques run unchanged.
//!
//! XFS has no equivalent of the ext4 journal recovery yet: its log holds
//! operations, not block copies.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use fs_core::BlockRead;
use fs_xfs::inode::Inode;
use fs_xfs::Filesystem;

use super::linux_image::{Extracted, HOME_DIRS, HOME_FILES, LINUX_DIRS, LINUX_FILES, MAX_DEPTH, MAX_FILES, MAX_FILE_BYTES};
use crate::errors::FaramirError;
use crate::windows::diag;

struct Copier<'a> {
    fs: &'a Filesystem,
    out: &'a Path,
    label: &'a str,
    stats: Extracted,
    seen: HashSet<String>,
    usr_merged: bool,
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

/// Resolve a symlink target relative to the directory holding the link.
fn resolve_link(dir: &str, target: &str) -> String {
    let joined = if target.starts_with('/') { target.to_string() } else { join(dir, target) };
    let mut parts: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    format!("/{}", parts.join("/"))
}

impl Copier<'_> {
    fn dest(&self, linux_path: &str) -> std::path::PathBuf {
        self.out.join(linux_path.trim_start_matches('/').replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    /// Inode of a path, with symlinks in the final component followed (one hop chain, bounded).
    fn open(&self, path: &str, hops: usize) -> Option<(Inode, Vec<u8>, String)> {
        if hops > 8 {
            return None;
        }
        let inode = self.fs.lookup_path(path).ok()?;
        let (inode, raw) = self.fs.read_inode_raw(inode.ino).ok()?;
        if inode.is_symlink() {
            let target = self.fs.read_link(&inode, &raw).ok()?;
            let target = String::from_utf8_lossy(&target).to_string();
            let dir = path.rsplit_once('/').map(|(d, _)| if d.is_empty() { "/" } else { d }).unwrap_or("/");
            return self.open(&resolve_link(dir, &target), hops + 1);
        }
        Some((inode, raw, path.to_string()))
    }

    fn copy_file(&mut self, linux_path: &str) {
        if self.stats.files >= MAX_FILES || !self.seen.insert(linux_path.to_string()) {
            return;
        }
        let Some((inode, raw, _)) = self.open(linux_path, 0) else { return };
        if !inode.is_regular_file() {
            return;
        }
        if inode.size > MAX_FILE_BYTES {
            self.stats.skipped_large += 1;
            diag::record(FaramirError::LinuxExtractError(format!(
                "{}: {linux_path} is {} bytes, above the {} MB limit",
                self.label,
                inode.size,
                MAX_FILE_BYTES >> 20
            )));
            return;
        }
        match self.fs.read_file(&inode, &raw) {
            Ok(data) => {
                let dest = self.dest(linux_path);
                if let Some(p) = dest.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                match std::fs::write(&dest, &data) {
                    Ok(()) => {
                        self.stats.files += 1;
                        self.stats.bytes += data.len() as u64;
                        if let Some(t) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(inode.mtime.sec.max(0) as u64)) {
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
        let Some((inode, raw, _)) = self.open(linux_dir, 0) else { return };
        if !inode.is_dir() {
            return;
        }
        let entries = match self.fs.read_dir(&inode, &raw) {
            Ok(e) => e,
            Err(e) => {
                diag::record(FaramirError::LinuxExtractError(format!("{}: {linux_dir}: {e}", self.label)));
                return;
            }
        };
        for e in entries {
            let name = String::from_utf8_lossy(&e.name).to_string();
            if name == "." || name == ".." {
                continue;
            }
            let path = join(linux_dir, &name);
            let Some((child, _, _)) = self.open(&path, 0) else { continue };
            if child.is_dir() {
                // a symlinked directory is not followed (loops, usr-merge)
                let is_link = self.fs.lookup_path(&path).map(|i| i.is_symlink()).unwrap_or(false);
                if !is_link {
                    self.copy_dir(&path, depth + 1);
                }
            } else if child.is_regular_file() {
                self.copy_file(&path);
            }
        }
    }
}

/// Copy the persistence surface of an XFS volume under `out_dir`.
pub fn extract_from_xfs(device: Arc<dyn BlockRead>, out_dir: &Path, label: &str) -> Result<Extracted, FaramirError> {
    let fs = Filesystem::mount(device).map_err(|e| FaramirError::XfsParseError(format!("{label}: {e}")))?;
    std::fs::create_dir_all(out_dir).map_err(|e| FaramirError::StagingDirFailed(format!("{}: {e}", out_dir.display())))?;
    let usr_merged = ["/lib", "/bin", "/sbin", "/lib64"].iter().any(|p| fs.lookup_path(p).map(|i| i.is_symlink()).unwrap_or(false));
    let mut c = Copier { fs: &fs, out: out_dir, label, stats: Extracted::default(), seen: HashSet::new(), usr_merged };
    for f in LINUX_FILES {
        c.copy_file(f);
    }
    for d in LINUX_DIRS {
        if c.usr_merged && ["/lib/", "/bin/", "/sbin/", "/lib64/"].iter().any(|t| d.starts_with(t) || *d == t.trim_end_matches('/')) {
            continue;
        }
        c.copy_dir(d, 0);
    }
    let mut homes: Vec<String> = vec!["/root".to_string()];
    if let Some((h, raw, _)) = c.open("/home", 0) {
        if let Ok(entries) = fs.read_dir(&h, &raw) {
            for e in entries {
                let n = String::from_utf8_lossy(&e.name).to_string();
                if n != "." && n != ".." {
                    if let Some((i, _, _)) = c.open(&format!("/home/{n}"), 0) {
                        if i.is_dir() {
                            homes.push(format!("/home/{n}"));
                        }
                    }
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
    c.stats.hostname = fs.read_path("/etc/hostname").ok().map(|b| String::from_utf8_lossy(&b).trim().to_string()).filter(|s| !s.is_empty());
    Ok(c.stats)
}
