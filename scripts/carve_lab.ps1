# Ground truth for `faramir --carve`, built on a real NTFS volume.
#
# Run as Administrator on a disposable Windows lab host (it toggles TRIM and
# takes a Volume Shadow Copy). It creates a 96 MiB fixed VHD, formats it NTFS
# and lays out:
#
#   live   Users\bob\NTUSER.DAT                 the operator's HKCU, saved with reg.exe
#          Windows\System32\config\DEFAULT      HKU\.DEFAULT
#   gone   Users\mallory\NTUSER.DAT             HKCU saved WITH a canary Run value that is
#                                               removed from the live registry right after
#          old\NTUSER.bak                       byte-identical copy of bob's hive
#          old\SYSTEM                           HKLM\SYSTEM (the big one)
#          old\SAM                              a hive with no persistence in it
#
# A shadow copy is taken with everything in place, then the `gone` files are
# deleted (TRIM off, so their clusters keep the data) and one new file is
# written so NTFS gets a chance to reuse space. The volume is detached and
# copied to carvelab.vhd; truth.json records the canary, the partition offset,
# the cluster size and the MFT record / extents of every file, so a carved
# hive can be matched to the clusters it came from.
#
# Expected from `faramir -f carvelab.vhd --carve`:
#   - the canary as windows:persistence:removed_since_vss:… (shadow copy) AND as
#     windows:persistence:carved:… at offset partition_offset + LCN * cluster
#   - old\NTUSER.bak reported as identical to an extracted hive, not carved twice
#   - old\SYSTEM carved whole (or as a prefix if the new file reused its clusters)
#   - no row for SAM
#
# Everything happens inside C:\rf-carve and on the VHD; TRIM is restored at the end.
$ErrorActionPreference = 'Stop'
$root = 'C:\rf-carve'
$vhd = "$root\work.vhd"
$letter = 'V'
$v = "${letter}:"
New-Item -ItemType Directory -Force $root | Out-Null
& vssadmin delete shadows /for=$v /quiet 2>$null | Out-Null
Remove-Item -Force "$root\*" -ErrorAction SilentlyContinue

$trimWas = (& fsutil behavior query DisableDeleteNotify) -join ' '
& fsutil behavior set DisableDeleteNotify 1 | Out-Null

function Run-Diskpart([string[]]$lines) {
    $script = "$root\dp.txt"
    Set-Content -Path $script -Value $lines -Encoding ASCII
    $out = & diskpart /s $script 2>&1
    if ($LASTEXITCODE -ne 0) { throw "diskpart failed: $out" }
    $out
}
function Save-Hive($key, $path) {
    $null = & reg.exe save $key $path /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg save $key failed" }
}
function File-Facts($path) {
    $fi = (& fsutil file queryfileid $path 2>&1) -join ' '
    $record = $null
    if ($fi -match '0x([0-9a-f]+)') { $record = [Convert]::ToInt64($matches[1].Substring([Math]::Max(0, $matches[1].Length - 12)), 16) -band 0xFFFFFFFFFFFF }
    $extents = @()
    foreach ($line in (& fsutil file queryextents $path 2>&1)) {
        if ($line -match 'VCN:\s*0x([0-9a-f]+)\s+Clusters:\s*0x([0-9a-f]+)\s+LCN:\s*0x([0-9a-f]+)') {
            $extents += [pscustomobject]@{
                vcn = [Convert]::ToInt64($matches[1], 16)
                clusters = [Convert]::ToInt64($matches[2], 16)
                lcn = [Convert]::ToInt64($matches[3], 16)
            }
        }
    }
    $head = [IO.File]::ReadAllBytes($path)[0..511]
    [pscustomobject]@{
        path = $path.Substring(2)
        size = (Get-Item $path).Length
        record = $record
        extents = $extents
        sha256 = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
        embedded = ([Text.Encoding]::Unicode.GetString($head[48..111]) -replace "`0", '')
        sequence = [BitConverter]::ToUInt32($head, 4)
        written_filetime = [BitConverter]::ToUInt64($head, 12)
        data_size = [BitConverter]::ToUInt32($head, 40)
    }
}

Run-Diskpart @(
    "create vdisk file=$vhd maximum=96 type=fixed",
    "select vdisk file=$vhd",
    "attach vdisk",
    "create partition primary",
    "format fs=ntfs quick label=CARVELAB",
    "assign letter=$letter"
) | Out-Null
Start-Sleep -Seconds 2
if (-not (Test-Path "$v\")) { throw "volume $v not mounted" }
$partOffset = (Get-Partition -DriveLetter $letter).Offset
$cluster = (Get-Volume -DriveLetter $letter).AllocationUnitSize

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
Remove-ItemProperty -Path $runKey -Name 'FaramirCanary' -ErrorAction SilentlyContinue

# --- stage 1: hives the file system keeps pointing to ------------------------
New-Item -ItemType Directory -Force "$v\Users\bob", "$v\Windows\System32\config" | Out-Null
Save-Hive 'HKCU' "$v\Users\bob\NTUSER.DAT"
Save-Hive 'HKU\.DEFAULT' "$v\Windows\System32\config\DEFAULT"

# --- stage 2: hives that will only survive in the raw bytes ------------------
$ts = Get-Date -Format 'yyyyMMddHHmmss'
$canary = "C:\carvetest\faramir_canary_$ts.exe"
Set-ItemProperty -Path $runKey -Name 'FaramirCanary' -Value $canary
New-Item -ItemType Directory -Force "$v\Users\mallory", "$v\old" | Out-Null
Save-Hive 'HKCU' "$v\Users\mallory\NTUSER.DAT"
Remove-ItemProperty -Path $runKey -Name 'FaramirCanary'
Copy-Item "$v\Users\bob\NTUSER.DAT" "$v\old\NTUSER.bak"
Save-Hive 'HKLM\SYSTEM' "$v\old\SYSTEM"
Save-Hive 'HKLM\SAM' "$v\old\SAM"
Write-VolumeCache $letter
Start-Sleep -Seconds 2

$facts = [ordered]@{
    bob = File-Facts "$v\Users\bob\NTUSER.DAT"
    default = File-Facts "$v\Windows\System32\config\DEFAULT"
    mallory = File-Facts "$v\Users\mallory\NTUSER.DAT"
    ntuser_bak = File-Facts "$v\old\NTUSER.bak"
    system = File-Facts "$v\old\SYSTEM"
    sam = File-Facts "$v\old\SAM"
}

# shadow copy with everything in place
$shadow = (& vssadmin create shadow /for=$v 2>&1) -join ' '
Start-Sleep -Seconds 3

# --- stage 3: delete, then give NTFS a reason to reuse space -----------------
Remove-Item -Recurse -Force "$v\Users\mallory"
Remove-Item -Recurse -Force "$v\old"
Start-Sleep -Seconds 2
$bytes = New-Object byte[] (300 * 1024)
(New-Object Random 7).NextBytes($bytes)
[IO.File]::WriteAllBytes("$v\Users\bob\recent.dat", $bytes)
Write-VolumeCache $letter
Start-Sleep -Seconds 2
$recent = File-Facts "$v\Users\bob\recent.dat"

Run-Diskpart @("select vdisk file=$vhd", "detach vdisk") | Out-Null
Copy-Item $vhd "$root\carvelab.vhd"
& fsutil behavior set DisableDeleteNotify 0 | Out-Null

[ordered]@{
    host = $env:COMPUTERNAME
    user = $env:USERNAME
    created_utc = (Get-Date).ToUniversalTime().ToString('o')
    canary = $canary
    partition_offset = $partOffset
    cluster_size = $cluster
    shadow = $shadow
    trim_before = $trimWas
    live = @('bob', 'default')
    deleted = @('mallory', 'ntuser_bak', 'system', 'sam')
    files = $facts
    recent = $recent
} | ConvertTo-Json -Depth 6 | Set-Content -Path "$root\truth.json" -Encoding UTF8

Get-FileHash "$root\carvelab.vhd", "$root\truth.json" -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash.ToLower())  $($_.Path)" } | Set-Content "$root\sha256.txt"
Get-Content "$root\sha256.txt"
"shadow: $shadow"
"canary: $canary"
"partition_offset=$partOffset cluster=$cluster"
foreach ($k in $facts.Keys) { "$k record=$($facts[$k].record) size=$($facts[$k].size) extents=" + (($facts[$k].extents | ForEach-Object { "lcn=$($_.lcn)+$($_.clusters)" }) -join ',') }
"recent extents=" + (($recent.extents | ForEach-Object { "lcn=$($_.lcn)+$($_.clusters)" }) -join ',')
