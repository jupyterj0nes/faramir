use chrono::Local;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vshadow::VssVolume;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const BITLOCKER_SIGNATURE: &[u8] = b"-FVE-FS-";

/// Paths to essential forensic execution and registry artifacts inside Windows NTFS
const EVTX_LOGS_PATH: &[&str] = &["Windows", "System32", "winevt", "Logs"];
const REG_CONFIG_PATH: &[&str] = &["Windows", "System32", "config"];
const AMCACHE_PATH: &[&str] = &["Windows", "AppCompat", "Programs"];
const TASKS_PATH: &[&str] = &["Windows", "System32", "Tasks"];

/// GPT partition type GUID for Microsoft Basic Data (includes NTFS)
const GPT_BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[FARAMIR {}] {}", timestamp, message);
    }
}

/// An EWF segment extension: `e01`..`e99` / `ex01`..
fn is_ewf_segment_ext(ext: &str) -> bool {
    let b = ext.as_bytes();
    (b.len() == 3 && b[0] == b'e' && b[1].is_ascii_digit() && b[2].is_ascii_alphanumeric())
        || (b.len() == 4 && b[0] == b'e' && b[1] == b'x' && b[2].is_ascii_alphanumeric() && b[3].is_ascii_alphanumeric())
}

/// Any file that belongs to a forensic image set, first segment or not.
pub fn is_image_file(path: &Path) -> bool {
    let filename = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };
    let Some((_, ext)) = filename.rsplit_once('.') else { return false };
    matches!(ext, "e01" | "ex01" | "vmdk" | "vhd" | "vhdx" | "dd" | "raw" | "img")
        || is_ewf_segment_ext(ext)
        || (ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()))
}

/// Is this the FIRST segment of an image set, the one to feed the pipeline?
/// `.E01` / `.Ex01`, the VMDK descriptor, `.vhd(x)`, `.dd/.raw/.img`, `.001`.
/// Secondary EWF segments, VMDK `-flat` / `-ctk` / `-sNNN` extents, VMware
/// snapshots (`-000001.vmdk`) and split-raw continuations (`.002`…) are not.
pub fn is_primary_image_segment(path: &Path) -> bool {
    let filename = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };
    if filename.ends_with(".e01") || filename.ends_with(".ex01") {
        return true;
    }
    if let Some((_, ext)) = filename.rsplit_once('.') {
        if is_ewf_segment_ext(ext) {
            return false;
        }
    }
    if let Some(stem) = filename.strip_suffix(".vmdk") {
        if stem.ends_with("-flat") || stem.ends_with("-ctk") {
            return false;
        }
        if let Some(pos) = stem.rfind("-s") {
            let a = &stem[pos + 2..];
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
        if let Some(pos) = stem.rfind("-0") {
            let a = &stem[pos + 1..];
            if a.len() >= 6 && a[..6].chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
        }
        return true;
    }
    if filename.ends_with(".vhd") || filename.ends_with(".vhdx") {
        return true;
    }
    if filename.ends_with(".dd") || filename.ends_with(".raw") || filename.ends_with(".img") || filename.ends_with(".001") {
        return true;
    }
    false
}

/// Checks if a file path is a supported forensic disk image (first segment only).
pub fn is_supported_image(path: &Path) -> bool {
    is_primary_image_segment(path)
}

/// `true` when the file is part of an image set but not its first segment.
pub fn is_secondary_image_segment(path: &Path) -> bool {
    is_image_file(path) && !is_primary_image_segment(path)
}

/// Wrapper that adds a byte offset to all Read/Seek operations, enabling partition-level I/O
struct OffsetReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> OffsetReader<'a, R> {
    fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<'a, R: Read + Seek> Read for OffsetReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, R: Read + Seek> Seek for OffsetReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => {
                let actual = self.inner.seek(SeekFrom::Start(self.offset + p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::Current(p) => {
                let actual = self.inner.seek(SeekFrom::Current(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::End(p) => {
                let actual = self.inner.seek(SeekFrom::End(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

/// Verifies whether the first bytes at a partition offset match the NTFS boot sector signature
fn verify_ntfs_signature<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 3)).is_err() {
        return false;
    }
    let mut sig = [0u8; 8];
    if reader.read_exact(&mut sig).is_err() {
        return false;
    }
    sig == NTFS_SIGNATURE
}

/// Verifies whether a partition is BitLocker encrypted
fn verify_bitlocker_signature<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 3)).is_err() {
        return false;
    }
    let mut sig = [0u8; 8];
    if reader.read_exact(&mut sig).is_err() {
        return false;
    }
    sig == BITLOCKER_SIGNATURE
}

/// Locates NTFS partitions by parsing MBR, GPT, and checking common volume offsets
fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R, image_size: u64) -> Result<Vec<u64>, String> {
    let mut partitions = Vec::new();

    if reader.seek(SeekFrom::Start(0)).is_err() {
        return Ok(partitions);
    }

    let mut mbr_buf = [0u8; 512];
    if reader.read_exact(&mut mbr_buf).is_ok() && mbr_buf[510] == 0x55 && mbr_buf[511] == 0xAA {
        let part0_type = mbr_buf[446 + 4];

        if part0_type == 0xEE {
            // GPT disk: parse GPT header and partition array
            if reader.seek(SeekFrom::Start(512)).is_ok() {
                let mut gpt_header = [0u8; 92];
                if reader.read_exact(&mut gpt_header).is_ok() && &gpt_header[0..8] == b"EFI PART" {
                    let part_entry_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap_or([0; 8]));
                    let num_parts = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap_or([0; 4]));
                    let part_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap_or([0; 4])) as usize;

                    let part_table_offset = part_entry_lba * 512;
                    if reader.seek(SeekFrom::Start(part_table_offset)).is_ok() {
                        for i in 0..num_parts.min(128) {
                            let entry_offset = part_table_offset + (i as u64 * part_size as u64);
                            if reader.seek(SeekFrom::Start(entry_offset)).is_ok() {
                                let mut entry_buf = vec![0u8; part_size.max(128)];
                                if reader.read_exact(&mut entry_buf).is_ok() {
                                    let type_guid: [u8; 16] = entry_buf[0..16].try_into().unwrap_or([0; 16]);
                                    if type_guid == GPT_BASIC_DATA_GUID {
                                        let first_lba = u64::from_le_bytes(entry_buf[32..40].try_into().unwrap_or([0; 8]));
                                        let part_offset = first_lba * 512;
                                        if part_offset < image_size && verify_ntfs_signature(reader, part_offset) {
                                            partitions.push(part_offset);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Standard MBR disk
            let mut cursor = std::io::Cursor::new(&mbr_buf[..]);
            if let Ok(mbr) = mbrman::MBR::read_from(&mut cursor, 512) {
                for (_, part) in mbr.iter() {
                    if !part.is_used() {
                        continue;
                    }
                    let part_offset = part.starting_lba as u64 * 512;
                    if part_offset < image_size && verify_ntfs_signature(reader, part_offset) {
                        partitions.push(part_offset);
                    }
                }
            }
        }
    }

    // Common fallback offsets (raw volume, 1MB alignment, 2048 sectors)
    if partitions.is_empty() {
        for &offset in &[0u64, 1024 * 1024, 2048 * 512, 63 * 512] {
            if offset < image_size && verify_ntfs_signature(reader, offset)
                && !partitions.contains(&offset)
            {
                partitions.push(offset);
            }
        }
    }

    Ok(partitions)
}

/// Extracts execution artifacts (EVTX, Registry, Amcache, Users) from an NTFS partition
/// Name of the staging folder for a partition or one of its shadow copies.
pub fn partition_dir_name(part_idx: usize, vss_store: Option<usize>) -> String {
    match vss_store {
        Some(s) => format!("partition_{part_idx}_vss_{s}"),
        None => format!("partition_{part_idx}"),
    }
}

/// Sidecar written next to the artifacts of a shadow copy.
pub const VSS_INFO_FILE: &str = "VSS_INFO.txt";

fn extract_artifacts_from_ntfs<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    output_dir: &Path,
    dir_name: &str,
) -> Result<usize, String> {
    let mut part_reader = OffsetReader::new(reader, partition_offset);

    let mut ntfs = ntfs::Ntfs::new(&mut part_reader).map_err(|e| format!("Cannot parse NTFS: {}", e))?;
    ntfs.read_upcase_table(&mut part_reader).map_err(|e| format!("Cannot read upcase table: {}", e))?;

    let root_dir = ntfs.root_directory(&mut part_reader).map_err(|e| format!("Cannot read root directory: {}", e))?;

    let part_dir = output_dir.join(dir_name);
    fs::create_dir_all(&part_dir).map_err(|e| e.to_string())?;

    let mut total_extracted = 0;

    // 1. Extract Windows EVTX logs (Windows\System32\winevt\Logs)
    if let Ok(evtx_dir) = navigate_to_path(&ntfs, &root_dir, &mut part_reader, EVTX_LOGS_PATH) {
        if let Ok(count) = dump_files_matching(&ntfs, &evtx_dir, &mut part_reader, &part_dir.join("Logs"), ".evtx") {
            total_extracted += count;
        }
    }

    // 2. Extract System Registry hives (Windows\System32\config: SYSTEM, SOFTWARE, SAM, SECURITY, and .LOG1/.LOG2)
    if let Ok(config_dir) = navigate_to_path(&ntfs, &root_dir, &mut part_reader, REG_CONFIG_PATH) {
        if let Ok(count) = dump_registry_config_files(&ntfs, &config_dir, &mut part_reader, &part_dir.join("config")) {
            total_extracted += count;
        }
    }

    // 3. Extract Amcache.hve (Windows\AppCompat\Programs\Amcache.hve)
    if let Ok(amcache_dir) = navigate_to_path(&ntfs, &root_dir, &mut part_reader, AMCACHE_PATH) {
        if let Ok(count) = dump_files_matching(&ntfs, &amcache_dir, &mut part_reader, &part_dir.join("AppCompat"), ".hve") {
            total_extracted += count;
        }
    }

    // 4. Extract User hives (Users\<username>\NTUSER.DAT and UsrClass.dat)
    if let Ok(users_dir) = navigate_to_path(&ntfs, &root_dir, &mut part_reader, &["Users"]) {
        if let Ok(count) = dump_user_hives(&ntfs, &users_dir, &mut part_reader, &part_dir.join("Users")) {
            total_extracted += count;
        }
    }

    // 5. Extract Windows Scheduled Tasks (Windows\System32\Tasks)
    if let Ok(tasks_dir) = navigate_to_path(&ntfs, &root_dir, &mut part_reader, TASKS_PATH) {
        if let Ok(count) = dump_all_files_recursive(&ntfs, &tasks_dir, &mut part_reader, &part_dir.join("System32_Tasks")) {
            total_extracted += count;
        }
    }

    Ok(total_extracted)
}

/// Navigates through NTFS directories matching a path component array (case-insensitive)
fn navigate_to_path<'a, R: Read + Seek>(
    ntfs: &'a ntfs::Ntfs,
    root: &'a ntfs::NtfsFile<'a>,
    reader: &mut R,
    path_components: &[&str],
) -> Result<ntfs::NtfsFile<'a>, String> {
    let mut current_dir = root.clone();

    for &component in path_components {
        let index = current_dir.directory_index(reader).map_err(|e| e.to_string())?;
        let mut found_ref = None;

        let mut entries = index.entries();
        while let Some(entry_res) = entries.next(reader) {
            let entry = entry_res.map_err(|e| e.to_string())?;
            if let Some(Ok(key)) = entry.key() {
                if key.name().to_string_lossy().eq_ignore_ascii_case(component) {
                    found_ref = Some(entry.file_reference());
                    break;
                }
            }
        }

        match found_ref {
            Some(f_ref) => {
                current_dir = f_ref.to_file(ntfs, reader).map_err(|e| e.to_string())?;
            }
            None => return Err(format!("Directory not found: {}", component)),
        }
    }

    Ok(current_dir)
}

/// Dumps files matching an extension from an NTFS directory to disk
fn dump_files_matching<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
    ext_suffix: &str,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            if name.to_lowercase().ends_with(ext_suffix) {
                if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                    if dump_ntfs_file_data(&file, reader, &dest.join(&name)).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Dumps all files recursively from an NTFS directory
fn dump_all_files_recursive<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            if name == "." || name == ".." || name.starts_with('$') {
                continue;
            }
            if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                if key.is_directory() {
                    if let Ok(c) = dump_all_files_recursive(ntfs, &file, reader, &dest.join(&name)) {
                        count += c;
                    }
                } else {
                    if dump_ntfs_file_data(&file, reader, &dest.join(&name)).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Dumps SYSTEM, SOFTWARE, SAM, SECURITY, and associated transaction logs from Windows\System32\config
fn dump_registry_config_files<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let target_stems = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];

    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            let upper = name.to_uppercase();

            let matches = target_stems.iter().any(|&stem| {
                upper == stem
                    || upper == format!("{}.LOG", stem)
                    || upper == format!("{}.LOG1", stem)
                    || upper == format!("{}.LOG2", stem)
            });

            if matches {
                if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                    if dump_ntfs_file_data(&file, reader, &dest.join(&name)).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Dumps NTUSER.DAT and UsrClass.dat across user profiles in Users directory
fn dump_user_hives<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    users_dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = users_dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let mut user_dirs = Vec::new();
    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            if name != "." && name != ".." && !name.starts_with('$') && key.is_directory() {
                user_dirs.push((name, entry.file_reference()));
            }
        }
    }

    for (username, u_ref) in user_dirs {
        if let Ok(user_dir) = u_ref.to_file(ntfs, reader) {
            if let Ok(u_index) = user_dir.directory_index(reader) {
                let mut u_entries = u_index.entries();
                while let Some(Ok(entry)) = u_entries.next(reader) {
                    if let Some(Ok(key)) = entry.key() {
                        let fname = key.name().to_string_lossy().to_string();
                        let upper = fname.to_uppercase();

                        if upper.starts_with("NTUSER.DAT") {
                            let out_name = format!("{}_{}", username, fname);
                            if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                                if dump_ntfs_file_data(&file, reader, &dest.join(&out_name)).is_ok() {
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Dumps raw data stream of an NTFS file to an output file path
fn dump_ntfs_file_data<R: Read + Seek>(file: &ntfs::NtfsFile, reader: &mut R, out_path: &Path) -> Result<(), io::Error> {
    let data_item = match file.data(reader, "") {
        Some(Ok(d)) => d,
        _ => return Err(io::Error::new(io::ErrorKind::NotFound, "No data attribute")),
    };

    let data_attr = data_item.to_attribute().map_err(|e| io::Error::other(e.to_string()))?;
    let data_val = data_attr.value(reader).map_err(|e| io::Error::other(e.to_string()))?;
    let mut attached = data_val.attach(reader);

    let mut out_file = File::create(out_path)?;
    let mut buf = [0u8; 65536];

    loop {
        match attached.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out_file.write_all(&buf[..n])?,
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Walks every Volume Shadow Copy of an NTFS partition and extracts the same
/// artifacts as from the live volume into `partition_<idx>_vss_<store>/`,
/// with a `VSS_INFO.txt` sidecar carrying the snapshot's creation time.
/// Returns the number of files extracted across all stores.
fn extract_vss_stores<R: Read + Seek>(reader: &mut R, part_offset: u64, out_dir: &Path, idx: usize, silent: bool) -> usize {
    let mut part_reader = OffsetReader::new(reader, part_offset);
    let vss = match VssVolume::new(&mut part_reader) {
        Ok(v) => v,
        Err(_) => return 0, // no VSS structures on this volume
    };
    let count = vss.store_count();
    if count == 0 {
        return 0;
    }
    log_message(
        silent,
        &format!("  ├─ Detected {} Volume Shadow Copy (VSS) store(s) on Partition {}", count, idx + 1),
    );
    let mut total = 0usize;
    for s in 0..count {
        let info = vss.store_info(s).ok();
        let created = info.as_ref().map(|i| i.creation_time_utc()).unwrap_or_else(|| "unknown".to_string());
        let sequence = info.as_ref().map(|i| i.sequence).unwrap_or(0);
        let dir_name = partition_dir_name(idx, Some(s));
        log_message(silent, &format!("  ├─ VSS store {} (created {}): extracting artifacts...", s, created));

        let mut store_reader = match vss.store_reader(&mut part_reader, s) {
            Ok(r) => r,
            Err(e) => {
                crate::windows::diag::record(crate::errors::FaramirError::VssParseError(format!(
                    "partition {} store {}: {}",
                    idx + 1,
                    s,
                    e
                )));
                continue;
            }
        };
        match extract_artifacts_from_ntfs(&mut store_reader, 0, out_dir, &dir_name) {
            Ok(n) => {
                total += n;
                let sidecar = out_dir.join(&dir_name).join(VSS_INFO_FILE);
                let _ = fs::write(
                    &sidecar,
                    format!("store={s}\npartition={idx}\ncreated={created}\nsequence={sequence}\n"),
                );
                log_message(silent, &format!("  │    {} artifacts extracted from VSS store {}", n, s));
            }
            Err(e) => {
                crate::windows::diag::record(crate::errors::FaramirError::VssParseError(format!(
                    "partition {} store {} (created {}): {}",
                    idx + 1,
                    s,
                    created,
                    e
                )));
            }
        }
    }
    total
}

/// Unpacks forensic execution artifacts from an E01 or RAW disk image into a destination staging directory
pub fn unpack_disk_image(
    image_path: &Path,
    dest_staging: &Path,
    silent: bool,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let stem = image_path.file_stem().and_then(|s| s.to_str()).unwrap_or("disk_image");
    let out_dir = dest_staging.join(stem);
    fs::create_dir_all(&out_dir)?;

    let path_str = image_path.to_string_lossy().to_string();
    let lower = path_str.to_lowercase();

    log_message(silent, &format!("💿 Opening forensic disk image: {}", image_path.display()));

    if lower.ends_with(".e01") || lower.ends_with(".ex01") {
        let ewf_reader = ewf::EwfReader::open(&path_str)
            .map_err(|e| crate::errors::FaramirError::EwfInitFailed(format!("{}: {e}", image_path.display())).to_string())?;
        let total_size = ewf_reader.total_size();
        log_message(
            silent,
            &format!("  ├─ E01 acquired capacity: {:.2} GB", total_size as f64 / 1_073_741_824.0),
        );

        let buf_reader = BufReader::new(ewf_reader);
        process_seekable_image(buf_reader, total_size, &out_dir, silent)?;
    } else if lower.ends_with(".vmdk") {
        let reader = super::vmdk::VmdkReader::open(&path_str).map_err(|e| {
            let msg = format!("{}: {e}", image_path.display());
            if e.contains("Incomplete VMDK") || e.contains("truncated") {
                crate::errors::FaramirError::ImageIncomplete(msg).to_string()
            } else {
                crate::errors::FaramirError::VmdkOpenFailed(msg).to_string()
            }
        })?;
        let total_size = reader.total_size();
        log_message(
            silent,
            &format!("  ├─ VMDK virtual disk capacity: {:.2} GB", total_size as f64 / 1_073_741_824.0),
        );
        let buf_reader = BufReader::new(reader);
        process_seekable_image(buf_reader, total_size, &out_dir, silent)?;
    } else if lower.ends_with(".vhd") || lower.ends_with(".vhdx") {
        let (reader, total_size) = super::vhd::open_virtual_disk(&path_str).map_err(|e| {
            let msg = format!("{}: {e}", image_path.display());
            if e.contains("differencing") {
                crate::errors::FaramirError::ImageIncomplete(msg).to_string()
            } else {
                crate::errors::FaramirError::VhdOpenFailed(msg).to_string()
            }
        })?;
        log_message(
            silent,
            &format!("  ├─ VHD/VHDX virtual disk capacity: {:.2} GB", total_size as f64 / 1_073_741_824.0),
        );
        let buf_reader = BufReader::new(reader);
        process_seekable_image(buf_reader, total_size, &out_dir, silent)?;
    } else {
        let file = File::open(image_path)?;
        let total_size = file.metadata()?.len();
        log_message(
            silent,
            &format!("  ├─ RAW disk image capacity: {:.2} GB", total_size as f64 / 1_073_741_824.0),
        );

        let buf_reader = BufReader::new(file);
        process_seekable_image(buf_reader, total_size, &out_dir, silent)?;
    }

    Ok(out_dir)
}

/// Suffix of the folder holding what the ext4 journal gave back for a volume.
pub const RECOVERED_SUFFIX: &str = ".recovered";

/// Deleted files and previous versions from an ext volume's journal, staged
/// next to the volume as `<dir>.recovered`. Returns the number of files written.
fn recover_from_volume(reader: &mut dyn ext4_view::Ext4Read, out_dir: &Path, dir: &str, label: &str, silent: bool) -> usize {
    use super::ext_journal as ej;
    let report = match ej::recover(reader, label) {
        Ok(r) => r,
        Err(e) => {
            crate::windows::diag::record(e);
            return 0;
        }
    };
    let j = report.journal.as_ref();
    if report.files.is_empty() {
        crate::windows::diag::record(crate::errors::FaramirError::ExtJournalEmpty(format!(
            "{label}: {} block copies in {} descriptor(s), {} inode-table and {} directory copies, nothing under the persistence surface",
            j.map(|j| j.copies).unwrap_or(0),
            j.map(|j| j.descriptors).unwrap_or(0),
            report.inode_copies,
            report.dir_copies
        )));
        return 0;
    }
    let target = out_dir.join(format!("{dir}{RECOVERED_SUFFIX}"));
    let entries = match ej::stage(&report, &target, label) {
        Ok(e) => e,
        Err(e) => {
            crate::windows::diag::record(e);
            return 0;
        }
    };
    let mut written = 0usize;
    for e in &entries {
        if e.content_recovered {
            written += 1;
            crate::windows::diag::record(crate::errors::FaramirError::ExtDeletedRecovered(format!(
                "{label}: {} {} ({} bytes, {}, mtime {}{})",
                e.kind,
                e.path,
                e.size,
                e.source,
                e.mtime,
                e.dtime.as_deref().map(|d| format!(", deleted {d}")).unwrap_or_default()
            )));
        } else {
            crate::windows::diag::record(crate::errors::FaramirError::ExtDeletedContentReused(format!(
                "{label}: {} {} ({}{})",
                e.kind,
                e.path,
                e.source,
                e.dtime.as_deref().map(|d| format!(", deleted {d}")).unwrap_or_default()
            )));
        }
    }
    log_message(
        silent,
        &format!(
            "  │    journal: {} deleted file(s) and {} previous version(s) under the persistence surface, {} with content",
            entries.iter().filter(|e| e.kind == "deleted").count(),
            entries.iter().filter(|e| e.kind == "previous_version").count(),
            written
        ),
    );
    written
}

/// Processes a seekable disk image: locates partitions, extracts Windows
/// artifacts and Volume Shadow Copies from NTFS volumes, the persistence
/// surface from Linux volumes (ext2/3/4, plain or in LVM), and reports every
/// other volume kind it recognises.
fn process_seekable_image<R: Read + Seek + Send + 'static>(
    reader: R,
    image_size: u64,
    out_dir: &Path,
    silent: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use super::linux_image::{self as lx, VolumeKind};
    let shared = lx::SharedReader::new(reader);
    let mut reader = shared.clone();
    let reader = &mut reader;

    let partitions = find_ntfs_partitions(reader, image_size).map_err(|e| format!("Partition scan error: {}", e))?;
    let volumes = lx::list_volumes(&shared, image_size);
    let linux: Vec<&lx::Volume> = volumes.iter().filter(|v| v.kind.is_readable_linux() || v.kind == VolumeKind::Lvm).collect();

    for v in &volumes {
        let what = format!("{} partition at offset {:#x} ({:.2} GB, {})", v.kind.label(), v.offset, v.size as f64 / 1_073_741_824.0, v.table);
        match v.kind {
            VolumeKind::Luks => {
                crate::windows::diag::record(crate::errors::FaramirError::LuksEncrypted(what));
            }
            k if k.is_unsupported_linux() => {
                crate::windows::diag::record(crate::errors::FaramirError::LinuxFsUnsupported(what));
            }
            _ => {}
        }
    }

    if partitions.is_empty() && linux.is_empty() {
        let seen: Vec<String> = volumes.iter().map(|v| format!("{} at {:#x}", v.kind.label(), v.offset)).collect();
        return Err(format!(
            "No NTFS or Linux (ext2/3/4, XFS, LVM) partitions found in disk image{}",
            if seen.is_empty() { " (no partition table, no known file system at offset 0)".to_string() } else { format!("; found: {}", seen.join(", ")) }
        )
        .into());
    }

    if !partitions.is_empty() {
        log_message(
            silent,
            &format!("  ├─ Found {} NTFS partition(s). Extracting forensic execution artifacts...", partitions.len()),
        );
    }

    let mut total_extracted = 0;

    for (idx, &part_offset) in partitions.iter().enumerate() {
        if verify_bitlocker_signature(reader, part_offset) {
            log_message(
                silent,
                &format!("  ⚠️ Partition {} at offset {:#x} is BitLocker encrypted (skipping)", idx + 1, part_offset),
            );
            continue;
        }

        match extract_artifacts_from_ntfs(reader, part_offset, out_dir, &partition_dir_name(idx, None)) {
            Ok(count) => {
                total_extracted += count;
                log_message(
                    silent,
                    &format!("  ├─ Partition {}: extracted {} execution artifacts (EVTX, Registry, Amcache)", idx + 1, count),
                );
            }
            Err(e) => {
                log_message(
                    silent,
                    &format!("  ⚠️ Warning: Partition {} extraction error: {}", idx + 1, e),
                );
            }
        }

        total_extracted += extract_vss_stores(reader, part_offset, out_dir, idx, silent);
    }

    if !linux.is_empty() {
        log_message(silent, &format!("  ├─ Found {} Linux volume(s). Extracting persistence surface...", linux.len()));
    }
    for (idx, v) in linux.iter().enumerate() {
        let part_idx = partitions.len() + idx;
        let label = format!("partition {} at offset {:#x}", part_idx + 1, v.offset);
        match v.kind {
            VolumeKind::Ext => {
                let dir = lx::linux_dir_name(part_idx, None);
                match lx::extract_from_ext(&shared, v.offset, &out_dir.join(&dir), &label) {
                    Ok(x) => {
                        total_extracted += x.files;
                        log_message(silent, &format!("  ├─ Partition {}: ext4, host '{}', {} file(s) staged", part_idx + 1, x.hostname.as_deref().unwrap_or("?"), x.files));
                        crate::windows::diag::record(crate::errors::FaramirError::LinuxVolumeExtracted(format!("{label}: {} file(s) into {dir}", x.files)));
                        let mut r = shared.at(v.offset);
                        total_extracted += recover_from_volume(&mut r, out_dir, &dir, &label, silent);
                    }
                    Err(e) => {
                        crate::windows::diag::record(e);
                    }
                }
            }
            VolumeKind::Xfs => {
                let dir = lx::linux_dir_name(part_idx, None);
                let device: std::sync::Arc<dyn fs_core::BlockRead> = std::sync::Arc::new(shared.at(v.offset));
                match super::xfs_image::extract_from_xfs(device, &out_dir.join(&dir), &label) {
                    Ok(x) => {
                        total_extracted += x.files;
                        log_message(silent, &format!("  ├─ Partition {}: XFS, host '{}', {} file(s) staged", part_idx + 1, x.hostname.as_deref().unwrap_or("?"), x.files));
                        crate::windows::diag::record(crate::errors::FaramirError::LinuxVolumeExtracted(format!("{label}: {} file(s) into {dir}", x.files)));
                    }
                    Err(e) => {
                        crate::windows::diag::record(e);
                    }
                }
            }
            VolumeKind::Lvm => match lx::list_logical_volumes(&shared, v.offset, &label) {
                Ok((lvm, lvs)) => {
                    log_message(silent, &format!("  ├─ Partition {}: LVM, {} logical volume(s)", part_idx + 1, lvs.len()));
                    for lv in &lvs {
                        let lv_label = format!("{label}, LV {}/{}", lv.vg, lv.name);
                        match lv.kind {
                            VolumeKind::Ext => {
                                let dir = lx::linux_dir_name(part_idx, Some(lv));
                                match lx::extract_from_lv(&shared, v.offset, std::sync::Arc::clone(&lvm), lv, &out_dir.join(&dir), &lv_label) {
                                    Ok(x) => {
                                        total_extracted += x.files;
                                        log_message(silent, &format!("  │    LV {}/{}: ext4, host '{}', {} file(s) staged", lv.vg, lv.name, x.hostname.as_deref().unwrap_or("?"), x.files));
                                        crate::windows::diag::record(crate::errors::FaramirError::LinuxVolumeExtracted(format!("{lv_label}: {} file(s) into {dir}", x.files)));
                                        let mut r = lx::lv_ext4_reader(&shared, v.offset, std::sync::Arc::clone(&lvm), lv);
                                        total_extracted += recover_from_volume(&mut *r, out_dir, &dir, &lv_label, silent);
                                    }
                                    Err(e) => {
                                        crate::windows::diag::record(e);
                                    }
                                }
                            }
                            VolumeKind::Xfs => {
                                let dir = lx::linux_dir_name(part_idx, Some(lv));
                                let device = lx::lv_block_device(&shared, v.offset, std::sync::Arc::clone(&lvm), lv);
                                match super::xfs_image::extract_from_xfs(device, &out_dir.join(&dir), &lv_label) {
                                    Ok(x) => {
                                        total_extracted += x.files;
                                        log_message(silent, &format!("  │    LV {}/{}: XFS, host '{}', {} file(s) staged", lv.vg, lv.name, x.hostname.as_deref().unwrap_or("?"), x.files));
                                        crate::windows::diag::record(crate::errors::FaramirError::LinuxVolumeExtracted(format!("{lv_label}: {} file(s) into {dir}", x.files)));
                                    }
                                    Err(e) => {
                                        crate::windows::diag::record(e);
                                    }
                                }
                            }
                            _ => {
                                crate::windows::diag::record(crate::errors::FaramirError::LinuxFsUnsupported(format!("{lv_label}: no ext2/3/4 or XFS signature ({} bytes, swap or data volume?)", lv.size)));
                            }
                        }
                    }
                }
                Err(e) => {
                    crate::windows::diag::record(e);
                }
            },
            _ => {}
        }
    }

    log_message(
        silent,
        &format!("  └─ Disk image extraction completed. Total staged artifacts: {}", total_extracted),
    );

    Ok(())
}
