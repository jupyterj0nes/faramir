//! VMDK reader: exposes a VMware virtual disk as `Read + Seek`.
//!
//! Supports monolithic sparse, monolithic flat, split sparse (`-s001.vmdk`…),
//! split flat (`-flat.vmdk`), `ZERO` extents and streamOptimized (compressed
//! grains, grain directory in the footer). Ported from masstin.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use flate2::read::ZlibDecoder;

const SECTOR_SIZE: u64 = 512;
const SPARSE_MAGIC: u32 = 0x564D_444B; // "KDMV"
const GD_AT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;

#[derive(Debug, Clone)]
struct SparseHeader {
    capacity: u64,
    grain_size: u64,
    num_gte_per_gt: u32,
    gd_offset: u64,
    compressed: bool,
}

enum ExtentData {
    Zero,
    Flat {
        file: File,
        file_offset: u64,
    },
    Sparse {
        file: File,
        header: SparseHeader,
        grain_directory: Vec<u32>,
        grain_table_cache: std::collections::HashMap<u32, Vec<u32>>,
        grain_data_cache: std::collections::HashMap<u64, Vec<u8>>,
    },
}

struct Extent {
    data: ExtentData,
    size_bytes: u64,
}

pub struct VmdkReader {
    extents: Vec<Extent>,
    total_size: u64,
    position: u64,
}

struct ExtentLineParts {
    sectors: u64,
    extent_type: String,
    filename: String,
    flat_offset: u64,
}

impl VmdkReader {
    /// Open a VMDK (descriptor, monolithic sparse or flat).
    pub fn open(path: &str) -> Result<Self, String> {
        let vmdk_path = Path::new(path);
        let base_dir = vmdk_path.parent().unwrap_or(Path::new("."));

        let mut file = File::open(path).map_err(|e| format!("Cannot open VMDK file '{}': {}", path, e))?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).map_err(|e| format!("Cannot read VMDK header: {}", e))?;
        let magic = u32::from_le_bytes(magic_buf);

        if magic == SPARSE_MAGIC {
            drop(file);
            let extent = Self::open_sparse_extent(path)?;
            let size = extent.size_bytes;
            return Ok(VmdkReader { extents: vec![extent], total_size: size, position: 0 });
        }

        drop(file);
        let mut file = File::open(path).map_err(|e| format!("Cannot open VMDK '{}': {}", path, e))?;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).map_err(|e| format!("Cannot read VMDK: {}", e))?;
        let text = String::from_utf8_lossy(&buf[..n]);

        if text.contains("# Disk DescriptorFile") || text.contains("createType") {
            Self::open_from_descriptor(&text, base_dir)
        } else {
            drop(file);
            let file = File::open(path).map_err(|e| format!("Cannot open raw VMDK: {}", e))?;
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            Ok(VmdkReader {
                extents: vec![Extent { data: ExtentData::Flat { file, file_offset: 0 }, size_bytes: size }],
                total_size: size,
                position: 0,
            })
        }
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Declared virtual size without opening extents (descriptor files are ~1 KB).
    pub fn probe_size(path: &str) -> Option<u64> {
        let mut file = File::open(path).ok()?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf).ok()?;
        if u32::from_le_bytes(magic_buf) == SPARSE_MAGIC {
            file.seek(SeekFrom::Start(0)).ok()?;
            let h = Self::read_sparse_header_at_current(&mut file).ok()?;
            return Some(h.capacity * SECTOR_SIZE);
        }
        drop(file);
        let mut file = File::open(path).ok()?;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        if !text.contains("# Disk DescriptorFile") && !text.contains("createType") {
            return None;
        }
        let mut total_sectors: u64 = 0;
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("RW ") && !line.starts_with("RDONLY ") && !line.starts_with("NOACCESS ") {
                continue;
            }
            if let Ok(parts) = Self::parse_extent_line(line) {
                total_sectors = total_sectors.saturating_add(parts.sectors);
            }
        }
        if total_sectors == 0 { None } else { Some(total_sectors * SECTOR_SIZE) }
    }

    fn open_from_descriptor(descriptor: &str, base_dir: &Path) -> Result<Self, String> {
        let mut extents = Vec::new();
        let mut total_size: u64 = 0;

        for line in descriptor.lines() {
            let line = line.trim();
            if !line.starts_with("RW ") && !line.starts_with("RDONLY ") && !line.starts_with("NOACCESS ") {
                continue;
            }
            let parts = Self::parse_extent_line(line)?;
            let extent_path = base_dir.join(&parts.filename);
            let extent_path_str = extent_path.to_string_lossy().to_string();

            let extent = match parts.extent_type.to_uppercase().as_str() {
                "FLAT" | "VMFS" | "VMFSRAW" | "VMFSRDM" => {
                    let f = match File::open(&extent_path) {
                        Ok(f) => f,
                        Err(_) => {
                            // incomplete SFTP uploads leave the data file as <name>.filepart
                            let filepart = format!("{}.filepart", extent_path_str);
                            match File::open(&filepart) {
                                Ok(f) => {
                                    eprintln!(
                                        "\x1b[33m[WARN]  Using incomplete upload '{}.filepart' for VMDK extent\x1b[0m",
                                        parts.filename
                                    );
                                    f
                                }
                                Err(_) => {
                                    return Err(format!(
                                        "Incomplete VMDK: flat extent '{}' not found (only descriptor was collected)",
                                        parts.filename
                                    ))
                                }
                            }
                        }
                    };
                    Extent {
                        data: ExtentData::Flat { file: f, file_offset: parts.flat_offset * SECTOR_SIZE },
                        size_bytes: parts.sectors * SECTOR_SIZE,
                    }
                }
                "SPARSE" | "VMFSSPARSE" => Self::open_sparse_extent(&extent_path_str)?,
                "ZERO" => Extent { data: ExtentData::Zero, size_bytes: parts.sectors * SECTOR_SIZE },
                other => return Err(format!("Unsupported extent type: {}", other)),
            };
            total_size += extent.size_bytes;
            extents.push(extent);
        }

        if extents.is_empty() {
            return Err("No extent lines found in VMDK descriptor".to_string());
        }
        Ok(VmdkReader { extents, total_size, position: 0 })
    }

    /// `ACCESS SECTORS TYPE "FILENAME" [OFFSET]`
    fn parse_extent_line(line: &str) -> Result<ExtentLineParts, String> {
        let mut chars = line.chars().peekable();
        let mut tokens: Vec<String> = Vec::new();
        loop {
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            if chars.peek().is_none() {
                break;
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                let mut tok = String::new();
                for c in chars.by_ref() {
                    if c == '"' {
                        break;
                    }
                    tok.push(c);
                }
                tokens.push(tok);
            } else {
                let mut tok = String::new();
                while chars.peek().is_some_and(|c| !c.is_whitespace()) {
                    tok.push(chars.next().unwrap());
                }
                tokens.push(tok);
            }
        }

        let is_zero = tokens.get(2).is_some_and(|t| t.eq_ignore_ascii_case("ZERO"));
        if tokens.len() < 4 && !(is_zero && tokens.len() == 3) {
            return Err(format!("Malformed extent line: {}", line));
        }
        let sectors: u64 = tokens[1].parse().map_err(|_| format!("Invalid sector count in extent line: {}", line))?;
        if sectors.checked_mul(SECTOR_SIZE).is_none() {
            return Err(format!("Sector count out of range in extent line: {}", line));
        }
        Ok(ExtentLineParts {
            sectors,
            extent_type: tokens[2].clone(),
            filename: tokens.get(3).cloned().unwrap_or_default(),
            flat_offset: if tokens.len() > 4 { tokens[4].parse().unwrap_or(0) } else { 0 },
        })
    }

    fn open_sparse_extent(path: &str) -> Result<Extent, String> {
        let mut file = File::open(path).map_err(|e| format!("Cannot open sparse extent '{}': {}", path, e))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| format!("Cannot seek to start: {}", e))?;
        let mut header = Self::read_sparse_header_at_current(&mut file)?;

        if header.gd_offset == GD_AT_END || header.gd_offset == 0 {
            if !header.compressed && header.capacity > 0 {
                return Err("Grain directory at end of file but not compressed: unsupported format".to_string());
            }
            let file_size = file.seek(SeekFrom::End(0)).map_err(|e| format!("Cannot seek to end: {}", e))?;
            let declared_bytes = header.capacity.saturating_mul(SECTOR_SIZE);
            let mut footer_header = None;
            let mut debug_info = format!("file_size={}", file_size);
            for offset_from_end in &[1024u64, 1536, 2048, 512] {
                let pos = file_size.saturating_sub(*offset_from_end);
                if file.seek(SeekFrom::Start(pos)).is_err() {
                    continue;
                }
                if let Ok(h) = Self::read_sparse_header_at_current(&mut file) {
                    if h.gd_offset != GD_AT_END && h.gd_offset != 0 && h.capacity > 0 {
                        footer_header = Some(h);
                        break;
                    }
                    debug_info.push_str(&format!(", at-{}:gd={}", offset_from_end, h.gd_offset));
                } else {
                    debug_info.push_str(&format!(", at-{}:no_magic", offset_from_end));
                }
            }
            let footer_header = footer_header.ok_or_else(|| {
                let gb = |b: u64| b as f64 / 1_073_741_824.0;
                if declared_bytes > 0 && file_size < declared_bytes {
                    format!(
                        "streamOptimized VMDK truncated: declared {:.1} GB, only {:.1} GB on disk, footer missing ({})",
                        gb(declared_bytes), gb(file_size), debug_info
                    )
                } else {
                    format!(
                        "streamOptimized VMDK: no valid footer found (declared {:.1} GB, file {:.1} GB, {})",
                        gb(declared_bytes), gb(file_size), debug_info
                    )
                }
            })?;
            header.gd_offset = footer_header.gd_offset;
        }

        let num_gd_entries = Self::gd_entry_count(&header);
        let gd_byte_offset = header.gd_offset.saturating_mul(SECTOR_SIZE);
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if (num_gd_entries as u64).saturating_mul(4) > file_len || gd_byte_offset >= file_len {
            return Err(format!(
                "Damaged sparse VMDK: grain directory of {} entries at byte {} does not fit in a {}-byte file",
                num_gd_entries, gd_byte_offset, file_len
            ));
        }
        file.seek(SeekFrom::Start(gd_byte_offset)).map_err(|e| format!("Cannot seek to grain directory: {}", e))?;
        let mut gd_buf = vec![0u8; num_gd_entries * 4];
        file.read_exact(&mut gd_buf).map_err(|e| format!("Cannot read grain directory: {}", e))?;
        let grain_directory: Vec<u32> = gd_buf
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let size_bytes = header.capacity * SECTOR_SIZE;
        Ok(Extent {
            data: ExtentData::Sparse {
                file,
                header,
                grain_directory,
                grain_table_cache: std::collections::HashMap::new(),
                grain_data_cache: std::collections::HashMap::new(),
            },
            size_bytes,
        })
    }

    fn read_sparse_header_at_current(file: &mut File) -> Result<SparseHeader, String> {
        let mut buf = [0u8; 72];
        file.read_exact(&mut buf).map_err(|e| format!("Cannot read sparse header: {}", e))?;
        if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != SPARSE_MAGIC {
            return Err("Not a sparse VMDK (bad magic)".to_string());
        }
        let flags = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let capacity = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let grain_size = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let num_gte_per_gt = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let gd_offset = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        let compressed = (flags & 0x10000) != 0;

        // VMware writes grainSize 128 and numGTEsPerGT 512; far-off values are damage.
        if grain_size == 0 || !grain_size.is_power_of_two() || grain_size > 2048 {
            return Err(format!("Damaged sparse VMDK header: grainSize {}", grain_size));
        }
        if num_gte_per_gt == 0 || num_gte_per_gt > 65536 {
            return Err(format!("Damaged sparse VMDK header: numGTEsPerGT {}", num_gte_per_gt));
        }
        if capacity.checked_mul(SECTOR_SIZE).is_none() {
            return Err(format!("Damaged sparse VMDK header: capacity {} sectors", capacity));
        }
        Ok(SparseHeader { capacity, grain_size, num_gte_per_gt, gd_offset, compressed })
    }

    fn gd_entry_count(header: &SparseHeader) -> usize {
        let sectors_per_gt = header.num_gte_per_gt as u64 * header.grain_size;
        if sectors_per_gt == 0 {
            return 0;
        }
        header.capacity.div_ceil(sectors_per_gt) as usize
    }

    fn find_extent(&self, global_offset: u64) -> Option<(usize, u64)> {
        let mut cumulative: u64 = 0;
        for (i, ext) in self.extents.iter().enumerate() {
            if global_offset < cumulative + ext.size_bytes {
                return Some((i, global_offset - cumulative));
            }
            cumulative += ext.size_bytes;
        }
        None
    }

    fn read_flat(file: &mut File, file_offset: u64, local_offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        file.seek(SeekFrom::Start(file_offset + local_offset))?;
        file.read(buf)
    }

    #[allow(clippy::too_many_arguments)]
    fn read_sparse(
        file: &mut File,
        header: &SparseHeader,
        grain_directory: &[u32],
        grain_table_cache: &mut std::collections::HashMap<u32, Vec<u32>>,
        grain_data_cache: &mut std::collections::HashMap<u64, Vec<u8>>,
        local_offset: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let grain_bytes = header.grain_size * SECTOR_SIZE;
        let extent_size = header.capacity * SECTOR_SIZE;
        if local_offset >= extent_size {
            return Ok(0);
        }
        let gte_per_gt = header.num_gte_per_gt as u64;
        let grain_index = (local_offset / SECTOR_SIZE) / header.grain_size;
        let gd_index = (grain_index / gte_per_gt) as usize;
        let gt_index = (grain_index % gte_per_gt) as usize;
        let offset_in_grain = local_offset % grain_bytes;
        let max_read = buf
            .len()
            .min((grain_bytes - offset_in_grain) as usize)
            .min((extent_size - local_offset) as usize);

        if gd_index >= grain_directory.len() {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }
        let gd_entry = grain_directory[gd_index];
        if gd_entry == 0 || gd_entry == 1 {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }
        let gt = Self::load_grain_table(file, grain_table_cache, gd_entry, gte_per_gt as usize)?;
        if gt_index >= gt.len() {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }
        let gt_entry = gt[gt_index];
        if gt_entry == 0 || gt_entry == 1 {
            buf[..max_read].fill(0);
            return Ok(max_read);
        }

        if header.compressed {
            if let Some(cached) = grain_data_cache.get(&grain_index) {
                let start = offset_in_grain as usize;
                let end = (start + max_read).min(cached.len());
                if start < cached.len() {
                    buf[..end - start].copy_from_slice(&cached[start..end]);
                    return Ok(end - start);
                }
                buf[..max_read].fill(0);
                return Ok(max_read);
            }
            // marker: { lba: u64, size: u32, data }
            file.seek(SeekFrom::Start(gt_entry as u64 * SECTOR_SIZE))?;
            let mut marker_buf = [0u8; 12];
            file.read_exact(&mut marker_buf)?;
            let compressed_size = u32::from_le_bytes(marker_buf[8..12].try_into().unwrap());
            if compressed_size == 0 || compressed_size > 10_000_000 {
                buf[..max_read].fill(0);
                return Ok(max_read);
            }
            let mut compressed_data = vec![0u8; compressed_size as usize];
            file.read_exact(&mut compressed_data)?;
            let mut decoder = ZlibDecoder::new(&compressed_data[..]);
            let mut decompressed = vec![0u8; grain_bytes as usize];
            let decompressed_len = decoder.read(&mut decompressed).unwrap_or(0);
            decompressed.truncate(decompressed_len);

            let start = offset_in_grain as usize;
            let end = (start + max_read).min(decompressed.len());
            if start < decompressed.len() {
                buf[..end - start].copy_from_slice(&decompressed[start..end]);
            } else {
                buf[..max_read].fill(0);
            }
            if grain_data_cache.len() > 1024 {
                grain_data_cache.clear();
            }
            grain_data_cache.insert(grain_index, decompressed);
            Ok(if start < decompressed_len { end - start } else { max_read })
        } else {
            file.seek(SeekFrom::Start(gt_entry as u64 * SECTOR_SIZE + offset_in_grain))?;
            file.read(&mut buf[..max_read])
        }
    }

    fn load_grain_table(
        file: &mut File,
        cache: &mut std::collections::HashMap<u32, Vec<u32>>,
        gd_entry: u32,
        num_entries: usize,
    ) -> io::Result<Vec<u32>> {
        if let Some(gt) = cache.get(&gd_entry) {
            return Ok(gt.clone());
        }
        file.seek(SeekFrom::Start(gd_entry as u64 * SECTOR_SIZE))?;
        let mut raw = vec![0u8; num_entries * 4];
        file.read_exact(&mut raw)?;
        let gt: Vec<u32> = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        cache.insert(gd_entry, gt.clone());
        Ok(gt)
    }
}

impl Read for VmdkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let Some((ext_idx, local_offset)) = self.find_extent(self.position) else { return Ok(0) };
        let extent = &mut self.extents[ext_idx];
        let read_len = buf.len().min((extent.size_bytes - local_offset) as usize);
        let n = match &mut extent.data {
            ExtentData::Zero => {
                buf[..read_len].fill(0);
                read_len
            }
            ExtentData::Flat { file, file_offset } => {
                let fo = *file_offset;
                Self::read_flat(file, fo, local_offset, &mut buf[..read_len])?
            }
            ExtentData::Sparse { file, header, grain_directory, grain_table_cache, grain_data_cache } => {
                Self::read_sparse(file, header, grain_directory, grain_table_cache, grain_data_cache, local_offset, &mut buf[..read_len])?
            }
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VmdkReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.total_size as i64 + offset,
            SeekFrom::Current(offset) => self.position as i64 + offset,
        };
        if new_pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Seek to a negative position"));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sparse_vmdk(name: &str, capacity: u64, grain: u64, gtes: u32) -> std::path::PathBuf {
        let mut img = vec![0u8; 65536];
        img[0..4].copy_from_slice(&SPARSE_MAGIC.to_le_bytes());
        img[4..8].copy_from_slice(&1u32.to_le_bytes());
        img[12..20].copy_from_slice(&capacity.to_le_bytes());
        img[20..28].copy_from_slice(&grain.to_le_bytes());
        img[44..48].copy_from_slice(&gtes.to_le_bytes());
        img[56..64].copy_from_slice(&1u64.to_le_bytes());
        let p = std::env::temp_dir().join(format!("faramir-vmdk-{}-{}.vmdk", name, std::process::id()));
        std::fs::write(&p, img).unwrap();
        p
    }

    #[test]
    fn damaged_sparse_headers_are_refused_not_trusted() {
        let p = sparse_vmdk("zero-gte", 2048, 128, 0);
        assert!(VmdkReader::open(p.to_str().unwrap()).is_err());
        let p2 = sparse_vmdk("huge", 1u64 << 41, 1, 1);
        assert!(VmdkReader::open(p2.to_str().unwrap()).is_err());
        let p3 = sparse_vmdk("sane", 2048, 128, 512);
        assert!(VmdkReader::open(p3.to_str().unwrap()).is_ok());
        for f in [p, p2, p3] {
            let _ = std::fs::remove_file(f);
        }
    }

    #[test]
    fn zero_extent_without_a_file_name_reads_zeros() {
        let parts = VmdkReader::parse_extent_line("RW 2048 ZERO").unwrap();
        assert_eq!(parts.extent_type, "ZERO");
        assert!(parts.filename.is_empty());
    }

    #[test]
    fn extent_line_with_quoted_name_and_offset() {
        let parts = VmdkReader::parse_extent_line(r#"RW 41943040 FLAT "my disk-flat.vmdk" 0"#).unwrap();
        assert_eq!(parts.sectors, 41943040);
        assert_eq!(parts.extent_type, "FLAT");
        assert_eq!(parts.filename, "my disk-flat.vmdk");
        assert_eq!(parts.flat_offset, 0);
        assert!(VmdkReader::parse_extent_line("RW abc FLAT \"x\"").is_err());
        assert!(VmdkReader::parse_extent_line("RW 1").is_err());
    }
}
