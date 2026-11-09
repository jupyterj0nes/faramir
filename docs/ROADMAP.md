# Roadmap

What is known to be missing or imperfect, in the order it is likely to matter. Each item says what is wrong today, so a reader can judge the output without waiting for the fix. Done items move to `CHANGELOG.md`.

## Precision of the rows

- **Rows read from files extracted out of a disk image carry the extraction, not the evidence.** Startup-folder entries, Group Policy scripts, forced browser extensions: `timestamp` is the moment faramir extracted the file and `commandline` holds the temporary folder (`…\Temp\faramir_img_<pid>_<n>\…`). They should carry the file's own modification time inside the image and its path in the volume. Until then those rows differ from run to run and `--carry-marks` never matches them.
- **Registry findings read with the generic value walker put the hive's path in the finding, not the key.** Run keys and the other `string_values_of_key` techniques: `source_file` shows the hive without the `:key` part the column promises. One line in `techniques.rs` plus the test assertions that encode the current behaviour.
- **VMware snapshot chains are skipped.** `disk-000001.vmdk` and later deltas are recognised as secondary segments and not read, so a VM with snapshots is analysed from its base disk, not its current state. Reading the chain (parent links, grain lookups falling through to the parent) is the fix.
- **WMI event subscriptions** (`wbem\Repository\OBJECTS.DATA`) are not read. The planted lab host's WMI consumer is the one technique faramir misses; caarea sees what it launches.

## Analysis

- **Composite rules.** Rules fire one by one; two medium findings on the same row never add up to `significant`. Whether they should is an analyst decision, not taken.
- **Rule points versus masstin's wording.** masstin's `hunt_score` is measured rarity throughout; faramir's rule points are measured per rule and per system on the clean reference hosts, but the reference is two lab hosts. More clean collections (Windows Server, RHEL) would tighten both the points and the stock lists.
- **`--known-good` and `--carry-marks`**: keep or remove. Both are implemented and tested; neither was asked for.
- **agentc00pr** has to learn faramir's own columns (`source_file`, `state`, `pid`, `reserved_*`) now that the header is no longer masstin's.

## Carving and images

- **Linux content carving** in free space once the ext4 journal has rotated.
- **`--carve-unalloc`**: scan only unallocated clusters (`$Bitmap` on NTFS, group bitmaps on ext4) instead of the whole image.
- **Dirty hives under memory pressure.** A dirty hive is replayed in memory and costs its size while its host is analysed. Writing the replayed copy to the staging folder and mapping it, as clean hives are mapped, would make a 1 GB `SOFTWARE` cost pages, not RAM.

## Speed

- **Console with several workers.** With `--jobs` above 1 the lines of targets running at the same time interleave (each line whole). A `MultiProgress` with one line per worker would replace them. The CSV and the diagnostics summary are unaffected.
- **Parallel work inside a host** (hives or techniques side by side) is not done; with memory-mapped hives a host takes seconds, so the gain is small and the `HiveSet` would need one handle per thread.
- **Parallel carving of one image** is not done: the scan is not the bottleneck (about 85 MB/s on a raw image with nothing in it, the techniques on the carved hives are), and on large disks the disk sets the pace.

## Housekeeping

- `LICENSE` file (the README says GPL-3.0).
- Line endings: some files are CRLF, some LF; a `.gitattributes` would stop the autocrlf warnings.
