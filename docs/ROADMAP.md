# Roadmap

What is known to be missing or imperfect, in the order it is likely to matter. Each item says what is wrong today, so a reader can judge the output without waiting for the fix. Done items move to `CHANGELOG.md`.

## Precision of the rows

- **Rows read from files extracted out of a disk image carry the extraction, not the evidence.** Startup-folder entries, Group Policy scripts, forced browser extensions: `timestamp` is the moment faramir extracted the file and `commandline` holds the temporary folder (`…\Temp\faramir_img_<pid>_<n>\…`). They should carry the file's own modification time inside the image and its path in the volume. Until then those rows differ from run to run, the `burst` clause of their `hunt_why` names the minute of the extraction instead of a real burst, and `--carry-marks` never matches them.
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
- **Largest targets first.** Workers take the targets in the order they were found; the run ends when the longest one does, so a big disk found last runs alone at the end. Dispatching by size, largest first, would not touch the CSV (the rows stay in the slot of their target).
- **A memory brake for the workers.** The default worker count is the threads the system gives the process, and what a worker costs in RAM (the replayed dirty hives of its host) is only known once the host is open. A shared budget a worker asks before replaying a hive, waiting when it does not fit, would protect a machine with little RAM without the user having to guess `--jobs`.
- **Parallel work inside a host** (hives or techniques side by side) is not done; with memory-mapped hives a host takes seconds, so the gain is small and the `HiveSet` would need one handle per thread.
- **Parallel carving of one image.** One image is one worker, and inside it the `regf` scan is a single pass on one thread: measured at 400 MB/s on a 1 GB raw image of random bytes with CPU time equal to wall time, so one core is saturated while an SSD waits (a 500 GB disk is 22 minutes of scan on one core; on a mechanical disk the disk already sets the pace and threads gain nothing). What it takes, with the output byte for byte the same: a range scan with overlap in `blockcarve` (the engine only scans start to end); one image reader per thread; finding separated from deciding, each thread validating and reading hives and returning candidates with their offset, the main thread applying today's logic in offset order (first copy wins, a hit inside an accepted hive is dropped as the skip does today, then the write); diagnostics per thread merged by offset; a shared progress bar; N threads hold N hives in flight. Tests: the lab image with 1 and N threads gives the same CSV; a synthetic image with hives planted on the chunk boundaries and inside the overlap, and the same hive in two chunks so the lower offset wins as today. The threads would be the `--jobs` ones: across targets when there are several, inside the carving when there is one.

## Housekeeping

- `LICENSE` file (the README says GPL-3.0).
- Line endings: some files are CRLF, some LF; a `.gitattributes` would stop the autocrlf warnings.
