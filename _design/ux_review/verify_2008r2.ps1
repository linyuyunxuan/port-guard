# =====================================================================
# PortGuard release verification - Windows Server 2008 R2 clean-machine
# Pure ASCII source. Read-only collector. Windows PowerShell 2.0 syntax.
# NO hardcoded version, zip filename or SHA256. Version and zip name are
# resolved at runtime; the independent expectation anchor lives OUTSIDE
# this script in verify_expect.txt.
#
# A2 is a THREE-WAY comparison: certutil actual hash vs the .sha256
# sidecar vs the INDEPENDENT anchor verify_expect.txt. The anchor file
# MUST be delivered through an INDEPENDENT channel (signed release
# announcement / signature page). DO NOT generate or ship it in the same
# batch as the zip + sidecar, or the anchor is worthless. A missing or
# malformed anchor is A2_ZIP_SHA256 HARD FAIL, never NEEDS-VISUAL.
#
# HARD RULES (do not remove):
#   * stdout and the report file are pure ASCII English only
#   * never create/delete firewall rules, never edit the database,
#     never edit product files, never repack the zip
#   * never launch the GUI; only "PortGuard.exe --diag --quiet" is run
#   * visual items are always NEEDS-VISUAL, never auto-PASSed
#   * zero lines of output is NEVER treated as a PASS
#
# Verdicts: PASS / FAIL / NEEDS-VISUAL
# The authoritative A4 gate is the --diag --quiet EXIT CODE (0 = clean),
# not the presence/absence of Chinese glyphs in the report text.
# =====================================================================

param(
    [string]$Root = "",
    [string]$Mode = "FULL",
    [string]$ExpectedLogPath = "",
    [string]$TestIp = "",
    [string]$ZipPath = "",
    [string]$ExpectPath = ""
)

# Suppress localized PowerShell errors so stdout stays pure ASCII English.
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"

# Deliberately NO hardcoded hash, zip filename or version constants here.
# Version and zip filename are resolved at runtime. The independent
# expectation anchor lives OUTSIDE this script in verify_expect.txt.
$REPORT_NAME = "verify_2008r2_report.txt"
$BASE_NAME   = "pg_rules_baseline.txt"
$EXPECT_NAME = "verify_expect.txt"

# ---------------------------------------------------------------- helpers

function Ascii([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return "" }
    $t = $s
    $t = $t -replace '\u2713', '[OK]'
    $t = $t -replace '\u2717', '[BAD]'
    $t = $t -replace '\u00B7', '*'
    $t = $t -replace '\uFF1A', ':'
    $t = $t -replace '[^\x20-\x7E]', '?'
    return $t
}

$script:Rpt = New-Object System.Text.StringBuilder
$script:States = New-Object System.Collections.ArrayList

# NOTE: do NOT name this function "R". In PowerShell "r" is a built-in alias
# for Invoke-History and aliases beat functions in command resolution, so
# every "R ..." call would silently go to history instead of the report.
function Note([string]$s) {
    [void]$script:Rpt.AppendLine((Ascii $s))
}
function W([string]$s) {
    $a = Ascii $s
    [void]$script:Rpt.AppendLine($a)
    Write-Host $a
}
function V([string]$id, [string]$state, [string]$detail) {
    W "[$state] $id :: $detail"
    [void]$script:States.Add($state)
}
function SplitLines([string]$s) {
    return @([regex]::Split($s, '\r\n|\n|\r'))
}

# Run a native command with a proper argument array (no cmd /c quote hell).
function Run([string]$exe, [string[]]$argv) {
    if ($null -eq $argv) { $argv = @() }
    $sb = New-Object System.Text.StringBuilder
    $code = -1
    try {
        $out = & $exe @argv 2>&1
        $code = $LASTEXITCODE
        foreach ($l in @($out)) { [void]$sb.AppendLine([string]$l) }
    } catch {
        # Never let a localized PowerShell error reach stdout.
        [void]$sb.AppendLine("RUN_ERROR: " + (Ascii $_.Exception.Message))
    }
    $o = New-Object PSObject
    $o | Add-Member NoteProperty Code $code
    $o | Add-Member NoteProperty Text $sb.ToString()
    return $o
}

# certutil -hashfile, tolerant of both continuous and space-separated hex.
function FileSha([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return "" }
    $r = Run "certutil.exe" @("-hashfile", $path, "SHA256")
    foreach ($line in (SplitLines $r.Text)) {
        $t = ([string]$line).Trim()
        if ($t -match '^([0-9A-Fa-f]{64})(\s|$)') {
            return $matches[1].ToLowerInvariant()
        }
        if ($t -match '^[0-9A-Fa-f]{2}(\s+[0-9A-Fa-f]{2}){31}\s*$') {
            return ($t -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
        }
    }
    return ""
}

function NormalizePath([string]$p) {
    if ([string]::IsNullOrEmpty($p)) { return "" }
    $x = $p.Trim().Trim('"').Trim()
    $x = $x -replace '/', '\'
    return $x.ToLowerInvariant()
}

# ---------------------------------------------------------------- paths

if ([string]::IsNullOrEmpty($Root)) {
    $p = $MyInvocation.MyCommand.Path
    if ($p) { $Root = Split-Path -Parent $p } else { $Root = (Get-Location).Path }
}
if ($Root.Length -gt 3 -and $Root.EndsWith('\')) { $Root = $Root.Substring(0, $Root.Length - 1) }
if ([string]::IsNullOrEmpty($Mode)) { $Mode = "FULL" }
$Mode = $Mode.ToUpperInvariant()

# ---- Package resolution: version / filename / hash are NEVER hardcoded ----
# Accept an explicit zip path (argument 4), otherwise auto-detect exactly one
# PortGuard-v*.zip next to the scripts. More than one candidate = hard FAIL,
# because silently picking one would be a false-green.
$zipPath = ""
$sidePath = ""
$zipName = ""
$version = ""
$zipSelectionError = ""
if (-not [string]::IsNullOrEmpty($ZipPath)) {
    $zipPath = $ZipPath
    $zipName = Split-Path -Leaf $zipPath
} else {
    $cands = @()
    if (Test-Path -LiteralPath $Root -PathType Container) {
        foreach ($f in @(Get-ChildItem -LiteralPath $Root -Filter "PortGuard-v*.zip" -ErrorAction SilentlyContinue)) {
            if ($f -is [System.IO.FileInfo]) { $cands += $f }
        }
    }
    if ($cands.Count -eq 1) {
        $zipPath = $cands[0].FullName
        $zipName = $cands[0].Name
    } elseif ($cands.Count -eq 0) {
        $zipSelectionError = "no PortGuard-v*.zip found; pass an explicit zip path as argument 4"
    } else {
        $names = @()
        foreach ($c in $cands) { $names += (Ascii $c.Name) }
        $zipSelectionError = "ambiguous: $($cands.Count) candidate zips ($([string]::Join(', ', $names))); pass ONE explicit zip path as argument 4"
    }
}
if (-not [string]::IsNullOrEmpty($zipPath)) { $sidePath = $zipPath + ".sha256" }
$mv = [regex]::Match($zipName, 'PortGuard-v([0-9]+\.[0-9]+\.[0-9]+)\.zip')
if ($mv.Success) { $version = $mv.Groups[1].Value }
$versionLabel = $version
if ([string]::IsNullOrEmpty($versionLabel)) { $versionLabel = "UNKNOWN" }
# If the version cannot be parsed, use a NEVER-MATCH pattern. Accepting a
# generic "PortGuard X.Y.Z ... False" line would let a historical startup
# line from an older build become this package's positive proof (false green).
$verPat = '[^\s\S]'
if (-not [string]::IsNullOrEmpty($version)) { $verPat = [regex]::Escape($version) }

# The extracted program folder sits next to the zip, not necessarily next
# to the scripts. Reports / baselines stay next to the scripts.
$pkgDir = $Root
if (-not [string]::IsNullOrEmpty($zipPath)) { $pkgDir = Split-Path -Parent $zipPath }
$pgDir     = Join-Path $pkgDir "PortGuard"
$exePath   = Join-Path $pgDir "PortGuard.exe"
$sumsPath  = Join-Path $pgDir "SHA256SUMS.txt"
$verPath   = Join-Path $pgDir "VERSION.txt"
$chgPath   = Join-Path $pgDir "04_CHANGELOG.txt"
$reportPath= Join-Path $Root $REPORT_NAME
$basePath  = Join-Path $Root $BASE_NAME

$appdata = $env:APPDATA
if ([string]::IsNullOrEmpty($appdata)) { $appdata = Join-Path $env:USERPROFILE "AppData\Roaming" }
$logsDir = Join-Path $appdata "PortGuard\logs"
$dbPath  = Join-Path $appdata "PortGuard\port_guard.db"

$windir = $env:WINDIR
if ([string]::IsNullOrEmpty($windir)) { $windir = "C:\Windows" }
$fontDir = Join-Path $windir "Fonts"

# ---- Independent expectation anchor (loaded at STARTUP) -----------------
# This is deliberately an EXTERNAL file, not a literal in this script.
# It must be delivered through an INDEPENDENT channel; see the .bat header
# and the report. A missing / malformed anchor is a HARD FAIL for A2.
$expectPath = Join-Path $Root $EXPECT_NAME
if (-not [string]::IsNullOrEmpty($ExpectPath)) { $expectPath = $ExpectPath }
$expectExists = (Test-Path -LiteralPath $expectPath -PathType Leaf)
$expectText = ""
if ($expectExists) {
    try { $expectText = [System.IO.File]::ReadAllText($expectPath, [System.Text.Encoding]::ASCII) } catch { $expectText = "" }
}
$expect = @{}
foreach ($el in (SplitLines $expectText)) {
    $et = ([string]$el).Trim()
    if ($et.StartsWith('#')) { continue }
    $eq = $et.IndexOf('=')
    if ($eq -gt 0) {
        $ek = $et.Substring(0, $eq).Trim()
        $ev = $et.Substring($eq + 1).Trim()
        if ($ek.Length -gt 0) { $expect[$ek] = $ev }
    }
}
$expSha = ""; $expVer = ""; $expSums = ""
if ($expect.ContainsKey("EXPECTED_ZIP_SHA"))       { $expSha  = [string]$expect["EXPECTED_ZIP_SHA"] }
if ($expect.ContainsKey("EXPECTED_VERSION"))      { $expVer  = [string]$expect["EXPECTED_VERSION"] }
if ($expect.ContainsKey("EXPECTED_SUMS_ENTRIES")) { $expSums = [string]$expect["EXPECTED_SUMS_ENTRIES"] }
$expectFieldsOk = ($expect.ContainsKey("EXPECTED_ZIP_SHA") -and
                   $expect.ContainsKey("EXPECTED_VERSION") -and
                   $expect.ContainsKey("EXPECTED_SUMS_ENTRIES"))
$expectShaOk  = ($expSha -match '^[0-9A-Fa-f]{64}$')
$expectVerOk  = ($expVer -match '^[0-9]+\.[0-9]+\.[0-9]+$')
$expectSumsOk = $false
if ($expSums -match '^[0-9]+$') { if ([int]$expSums -gt 0) { $expectSumsOk = $true } }
$expectFormatOk = ($expectFieldsOk -and $expectShaOk -and $expectVerOk -and $expectSumsOk)
$expectWhy = ""
if (-not $expectExists)       { $expectWhy = "verify_expect.txt is MISSING" }
elseif (-not $expectFieldsOk) { $expectWhy = "one or more EXPECTED_* fields are missing" }
elseif (-not $expectShaOk)    { $expectWhy = "EXPECTED_ZIP_SHA is not a 64-hex SHA256 (placeholder not filled)" }
elseif (-not $expectVerOk)    { $expectWhy = "EXPECTED_VERSION is not X.Y.Z" }
elseif (-not $expectSumsOk)   { $expectWhy = "EXPECTED_SUMS_ENTRIES is not a positive integer" }
$expectShaNorm = ""
if ($expectShaOk) { $expectShaNorm = $expSha.ToLowerInvariant() }
$expectSumsNum = 0
if ($expectSumsOk) { $expectSumsNum = [int]$expSums }

W "======================================================================"
W "PortGuard / Windows Server 2008 R2 clean-machine evidence"
W "Package version (from zip filename) : $versionLabel"
W "ASCII English only. READ-ONLY collector. Not a release signature."
W "Run time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
W "Mode     : $Mode"
W "Root     : $(Ascii $Root)"
W "Package  : $(Ascii $zipPath)"
W "Logs dir : $(Ascii $logsDir)"
W "Expect   : $(Ascii $expectPath)"
W "Expect anchor : present=$expectExists fieldsOK=$expectFieldsOk formatOK=$expectFormatOk"
W "----------------------------------------------------------------------"
W "ANTI-FALSE-GREEN RULES BUILT INTO THIS SCRIPT:"
W " 1. Empty / zero-line command output is NEVER a PASS; a positive-control"
W "    netsh command must succeed first."
W " 2. 'No new rules' is decided by exact rule-name SET DIFF, not by a line"
W "    count, a hash, or a log file getting bigger."
W " 3. 'No error string in log' is not a PASS unless a positive startup line"
W "    is present first."
W " 4. 'system also missing' in the diag report is ADVISORY on the Qt5 line"
W "    (ucrtbase.dll / KB2999226), never an automatic FAIL."
W " 5. --diag --quiet EXIT CODE 0 is the authoritative A4 gate."
W " 6. Every visual item is NEEDS-VISUAL. The script cannot see the screen."
W " 7. A2 is a THREE-WAY check: certutil actual vs sidecar vs the"
W "    independent verify_expect.txt anchor. A missing / malformed expect"
W "    file is A2_ZIP_SHA256 HARD FAIL, never NEEDS-VISUAL, never overridable."
W " 8. verify_expect.txt MUST arrive via an INDEPENDENT channel, never in"
W "    the same batch as the zip + sidecar, or the anchor is worthless."
W "======================================================================"
Note ""

# ============================================================ A. ENV
W "--- A. ENVIRONMENT AND INTEGRITY ---"

# A1 OS version
$rVer = Run "cmd.exe" @("/c", "ver")
$rSys = Run "systeminfo.exe" @()
# Read the registry through PowerShell's own provider (no external reg.exe,
# no localized console output). systeminfo is a locale-independent fallback.
$cv = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue

$verTok = ""
$m = [regex]::Match($rVer.Text, '[0-9]+\.[0-9]+\.[0-9]+')
if ($m.Success) { $verTok = $m.Value }
$sysTok = ""
$m = [regex]::Match($rSys.Text, '[0-9]+\.[0-9]+\.[0-9]+')
if ($m.Success) { $sysTok = $m.Value }
$buildNum = ""
$spText = ""
if ($cv) {
    $buildNum = [string]$cv.CurrentBuildNumber
    $spText   = [string]$cv.CSDVersion
}
$sysBuildHit = @()
foreach ($l in (SplitLines $rSys.Text)) {
    if ($l -match '7601|6\.1\.7601|Service Pack') { $sysBuildHit += (Ascii $l).Trim() }
}
Note "A1 RAW ver (sanitized)      : $(Ascii ($rVer.Text.Trim()))"
Note "A1 RAW build token          : $verTok"
Note "A1 REG CurrentBuildNumber   : $buildNum"
Note "A1 REG CSDVersion           : $(Ascii $spText)"
Note "A1 systeminfo version token : $sysTok"
Note "A1 systeminfo exit code      : $($rSys.Code)"
Note "A1 systeminfo matching lines : $($sysBuildHit.Count)"
foreach ($s in @($sysBuildHit | Select-Object -First 4)) { Note "A1 SYS> $s" }
if ($verTok -eq "6.1.7601" -and ($buildNum -eq "7601" -or $sysTok -eq "6.1.7601")) {
    V "A1_OS_VERSION" "PASS" "ver=$verTok build=$buildNum systeminfo=$sysTok; SP text recorded above"
} elseif ([string]::IsNullOrEmpty($verTok) -or ([string]::IsNullOrEmpty($buildNum) -and [string]::IsNullOrEmpty($sysTok))) {
    V "A1_OS_VERSION" "NEEDS-VISUAL" "could not read ver / registry / systeminfo build; confirm OS manually (winver screenshot)"
} else {
    V "A1_OS_VERSION" "FAIL" "expected 6.1.7601 / 7601, got ver=$verTok build=$buildNum systeminfo=$sysTok"
}
if ($spText -match 'Service Pack 1|SP1') {
    V "A1_SP1" "PASS" "CSDVersion says Service Pack 1"
} else {
    V "A1_SP1" "NEEDS-VISUAL" "SP1 string not matched (output may be localized); confirm with winver screenshot"
}

# A2 zip / sidecar / INDEPENDENT ANCHOR - three-way SHA256 comparison.
# The sidecar alone is NOT enough: if the zip AND the sidecar are swapped
# together, a two-way check still passes. verify_expect.txt is the third,
# independently delivered anchor, loaded at startup (see above).
W "--- A2 THREE-WAY SHA256 (CERTUTIL / SIDECAR / INDEPENDENT ANCHOR) ---"
Note "A2 PACKAGE PATH    : $(Ascii $zipPath)"
Note "A2 SIDECAR PATH    : $(Ascii $sidePath)"
Note "A2 EXPECT PATH     : $(Ascii $expectPath)"
Note "A2 PACKAGE VERSION : $versionLabel (parsed from zip filename)"
Note "A2 EXPECT VERSION  : $(Ascii $expVer)"
Note "A2 EXPECT SHA256   : $(Ascii $expSha)"
Note "A2 EXPECT SUMS ROWS: $(Ascii $expSums)"
$zipOk = $false; $sidOk = $false; $fmtOk = $false; $hashOk = $false
$anchorOk = $false; $versionMatchOk = $false
$zipHash = ""; $sideHash = ""; $sideName = ""; $sideHashCount = 0

# --- Independent anchor: presence and format are HARD FAIL conditions ---
if (-not $expectExists) {
    V "A2_EXPECT_PRESENT" "FAIL" "verify_expect.txt is MISSING. It must come from an INDEPENDENT channel (signed release announcement / signature page). Hard FAIL, no human override."
} else {
    V "A2_EXPECT_PRESENT" "PASS" "verify_expect.txt found: $(Ascii (Split-Path -Leaf $expectPath))"
}
if (-not $expectExists) {
    V "A2_EXPECT_FORMAT" "FAIL" "cannot parse fields: expect file missing. Hard FAIL, no human override."
} elseif (-not $expectFormatOk) {
    V "A2_EXPECT_FORMAT" "FAIL" "$expectWhy. Every EXPECTED_* field must hold a real value, not a placeholder. Hard FAIL, no human override."
} else {
    V "A2_EXPECT_FORMAT" "PASS" "EXPECTED_ZIP_SHA / EXPECTED_VERSION / EXPECTED_SUMS_ENTRIES present and well-formed"
}

if ([string]::IsNullOrEmpty($zipPath) -or -not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
    $why = "release zip not found; auto-detect PortGuard-v*.zip or pass explicit zip path as argument 4"
    if (-not [string]::IsNullOrEmpty($zipSelectionError)) { $why = $zipSelectionError }
    V "A2_ZIP_PRESENT" "FAIL" $why
} else {
    $zipOk = $true
    V "A2_ZIP_PRESENT" "PASS" "release zip found: $(Ascii $zipName)"
}
if ([string]::IsNullOrEmpty($version)) {
    V "A2_VERSION_PARSE" "FAIL" "cannot parse vX.Y.Z from zip filename; use PortGuard-vX.Y.Z.zip"
} else {
    V "A2_VERSION_PARSE" "PASS" "version label taken from zip filename: $version"
}

# Independent FAIL #1: sidecar missing.
if ([string]::IsNullOrEmpty($sidePath) -or -not (Test-Path -LiteralPath $sidePath -PathType Leaf)) {
    V "A2_SIDECAR_PRESENT" "FAIL" "sidecar <zipname>.sha256 is MISSING. Hard FAIL, no human override."
} else {
    $sidOk = $true
    V "A2_SIDECAR_PRESENT" "PASS" "sidecar found: $(Ascii (Split-Path -Leaf $sidePath))"
    try { $sideText = [System.IO.File]::ReadAllText($sidePath, [System.Text.Encoding]::ASCII) } catch { $sideText = "" }
    $hm = [regex]::Matches($sideText, '\b[0-9A-Fa-f]{64}\b')
    $sideHashCount = $hm.Count
    if ($hm.Count -ge 1) { $sideHash = $hm[0].Value.ToLowerInvariant() }
    $fm = [regex]::Match($sideText, '[0-9A-Fa-f]{64}\s+(\S+)')
    if ($fm.Success) { $sideName = $fm.Groups[1].Value.TrimStart('*') }
    Note "A2 SIDECAR EXPECTED SHA256 : $sideHash"
    Note "A2 SIDECAR FILE NAME TOKEN : $(Ascii $sideName)"
    Note "A2 SIDECAR 64-HEX TOKENS   : $sideHashCount"
    # Independent FAIL #2: sidecar malformed.
    if ($sideHashCount -ne 1 -or $sideHash.Length -ne 64 -or [string]::IsNullOrEmpty($sideName) -or $sideName -ine $zipName) {
        V "A2_SIDECAR_FORMAT" "FAIL" "sidecar must hold exactly one 64-hex hash followed by the exact zip filename. Hard FAIL, no human override."
    } else {
        $fmtOk = $true
        V "A2_SIDECAR_FORMAT" "PASS" "one 64-hex hash and the matching zip filename"
    }
}

if ($zipOk) { $zipHash = FileSha $zipPath }
Note "A2 CERTUTIL ACTUAL SHA256  : $zipHash"
# Independent FAIL #3: sidecar vs actual mismatch. Never overridable.
if (-not $zipOk) {
    V "A2_HASH_MATCH" "FAIL" "cannot compute certutil hash: zip absent. Hard FAIL, no human override."
} elseif ($zipHash.Length -ne 64) {
    V "A2_HASH_MATCH" "FAIL" "certutil did not return a 64-hex SHA256. Hard FAIL, no human override."
} elseif (-not $sidOk -or $sideHash.Length -ne 64) {
    V "A2_HASH_MATCH" "FAIL" "no valid expected hash in sidecar; cannot compare. Hard FAIL, no human override."
} elseif ($zipHash -ne $sideHash) {
    V "A2_HASH_MATCH" "FAIL" "MISMATCH actual=$zipHash expected=$sideHash. DO NOT USE THIS PACKAGE. Hard FAIL, no human override allowed."
} else {
    $hashOk = $true
    V "A2_HASH_MATCH" "PASS" "certutil actual SHA256 equals the sidecar expected SHA256"
}
# Independent FAIL #4: the independent anchor vs actual. This is the
# guard against "zip + sidecar swapped together". Never overridable.
if (-not $expectFormatOk) {
    V "A2_ANCHOR_MATCH" "FAIL" "no valid EXPECTED_ZIP_SHA in verify_expect.txt; cannot verify the independent anchor. Hard FAIL, no human override."
} elseif ($zipHash.Length -ne 64) {
    V "A2_ANCHOR_MATCH" "FAIL" "certutil did not return a 64-hex SHA256; cannot compare with the anchor. Hard FAIL, no human override."
} elseif ($zipHash -ne $expectShaNorm) {
    V "A2_ANCHOR_MATCH" "FAIL" "ANCHOR MISMATCH actual=$zipHash anchor=$expectShaNorm. The zip and its sidecar may have been swapped together. DO NOT USE THIS PACKAGE. Hard FAIL, no human override."
} else {
    $anchorOk = $true
    V "A2_ANCHOR_MATCH" "PASS" "certutil actual SHA256 equals the INDEPENDENT anchor EXPECTED_ZIP_SHA"
}

# Independent FAIL #5: version from zip filename vs independent anchor.
if (-not $expectFormatOk) {
    V "A2_VERSION_MATCH" "FAIL" "no valid EXPECTED_VERSION in verify_expect.txt; cannot verify version. Hard FAIL, no human override."
} elseif ([string]::IsNullOrEmpty($version)) {
    V "A2_VERSION_MATCH" "FAIL" "cannot parse vX.Y.Z from zip filename. Hard FAIL, no human override."
} elseif ($version -ne $expVer) {
    V "A2_VERSION_MATCH" "FAIL" "VERSION MISMATCH zip=$version anchor=$expVer. Hard FAIL, no human override."
} else {
    $versionMatchOk = $true
    V "A2_VERSION_MATCH" "PASS" "zip filename version equals the independent anchor EXPECTED_VERSION"
}

# THE named gate. Any missing / malformed / disagreeing input is a HARD
# FAIL. It is NEVER NEEDS-VISUAL and NEVER overridable by a human.
$a2Ok = ($zipOk -and $sidOk -and $fmtOk -and $hashOk -and $anchorOk -and
         $versionMatchOk -and $expectExists -and $expectFormatOk -and
         (-not [string]::IsNullOrEmpty($version)))
if ($a2Ok) {
    V "A2_ZIP_SHA256" "PASS" "THREE-WAY MATCH: certutil / sidecar / independent anchor all agree; version matches; zip filename parsed"
} else {
    V "A2_ZIP_SHA256" "FAIL" "one or more of zip / sidecar / independent anchor / version is missing, malformed or disagreeing. HARD FAIL, no human override. Sub-checks above show which."
}
if ($a2Ok) {
    V "A2_OVERALL" "PASS" "zip / sidecar / hash / anchor / version all consistent"
} else {
    V "A2_OVERALL" "FAIL" "one or more A2 sub-checks failed. A hash mismatch is NEVER overridable by a human."
}
V "A2_EXPECT_PROVENANCE" "NEEDS-VISUAL" "verify_expect.txt MUST have arrived through an INDEPENDENT channel (signed release announcement / signature page), NOT in the same batch as the zip + sidecar. Human must record the channel and evidence. This does NOT override A2_ZIP_SHA256."
V "A2_SIDECAR_PROVENANCE" "NEEDS-VISUAL" "residual supply-chain risk: if zip, sidecar AND the expect file are all swapped together, A2 still passes. Confirm the anchor hash via a second INDEPENDENT channel. This does NOT override A2_ZIP_SHA256."
Note "A2 NOTE: expected hash comes from BOTH the sidecar and the independent verify_expect.txt anchor. No version or hash is hardcoded in this script."

# A3 SHA256SUMS.txt per-file check (anti-zero-row)
W "--- A3 SHA256SUMS PER-FILE CHECK ---"
$sumChecked = 0; $sumMissing = 0; $sumMismatch = 0; $sumEntries = 0
$sumProblems = @()
if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
    V "A3_PER_FILE_SUMS" "NEEDS-VISUAL" "SHA256SUMS.txt not found; extract the zip to a pure ASCII path first"
} else {
    $sumsText = [System.IO.File]::ReadAllText($sumsPath, [System.Text.Encoding]::UTF8)
    foreach ($line in (SplitLines $sumsText)) {
        $t = ([string]$line).Trim()
        if ($t -match '^([0-9A-Fa-f]{64})\s+(.+)$') {
            $sumEntries++
            $want = $matches[1].ToLowerInvariant()
            $rel  = $matches[2].Trim()
            $rel2 = $rel -replace '/', '\'
            $full = Join-Path $pkgDir $rel2
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
                $sumMissing++
                if ($sumProblems.Count -lt 12) { $sumProblems += "MISSING $rel2" }
            } else {
                $got = FileSha $full
                $sumChecked++
                if ($got -ne $want) {
                    $sumMismatch++
                    if ($sumProblems.Count -lt 12) { $sumProblems += "MISMATCH $rel2 want=$want got=$got" }
                }
            }
        }
    }
    Note "A3 manifest entries (expected from verify_expect.txt) : $sumEntries / $expectSumsNum"
    Note "A3 files hashed : $sumChecked ; missing : $sumMissing ; mismatch : $sumMismatch"
    foreach ($s in $sumProblems) { Note "A3 ISSUE> $(Ascii $s)" }
    if ($sumEntries -eq 0) {
        V "A3_PER_FILE_SUMS" "FAIL" "manifest contained 0 hash entries. A zero-row result is NOT a PASS."
    } elseif ($sumMissing -eq 0 -and $sumMismatch -eq 0 -and $sumChecked -gt 0) {
        V "A3_PER_FILE_SUMS" "PASS" "$sumChecked files hashed, 0 missing, 0 mismatch"
    } else {
        V "A3_PER_FILE_SUMS" "FAIL" "missing=$sumMissing mismatch=$sumMismatch"
    }
}
# Manifest row count is checked against the INDEPENDENT anchor, never a
# literal in this script. A zero-row manifest is never a PASS.
if (-not $expectFormatOk) {
    V "A3_MANIFEST_COUNT" "FAIL" "no valid EXPECTED_SUMS_ENTRIES in verify_expect.txt; cannot verify the manifest row count"
} elseif ($sumEntries -eq 0) {
    V "A3_MANIFEST_COUNT" "FAIL" "0 hash rows observed. A zero-row result is NOT a PASS."
} elseif ($sumEntries -ne $expectSumsNum) {
    V "A3_MANIFEST_COUNT" "FAIL" "manifest rows=$sumEntries but EXPECTED_SUMS_ENTRIES=$expectSumsNum (independent anchor)"
} else {
    V "A3_MANIFEST_COUNT" "PASS" "manifest rows=$sumEntries equals EXPECTED_SUMS_ENTRIES=$expectSumsNum"
}

# A4 --diag --quiet
W "--- A4 PORTGUARD.EXE --diag --quiet ---"
Note "A4 diag report directory (core/diag.py _logs_dir) : $(Ascii $logsDir)"
Note "A4 expected report name pattern : diag-YYYYMMDD-HHMMSS.txt (UTF-8)"
$diagCode = -999
$diagErr = ""
$beforeNames = @{}
if (Test-Path -LiteralPath $logsDir -PathType Container) {
    foreach ($f in @(Get-ChildItem -LiteralPath $logsDir -Filter "diag-*.txt" -ErrorAction SilentlyContinue)) {
        $beforeNames[$f.Name] = $true
    }
}
$startTime = Get-Date
$diagTarget = $null
$diagText = ""
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    V "A4_DIAG_EXIT_0" "NEEDS-VISUAL" "PortGuard.exe not found at expected path; cannot run --diag"
} else {
    try {
        $pr = Start-Process -FilePath $exePath -ArgumentList "--diag --quiet" -WorkingDirectory (Split-Path -Parent $exePath) -Wait -PassThru
        if ($pr) { $diagCode = $pr.ExitCode }
    } catch {
        $diagErr = Ascii $_.Exception.Message
    }
    $fresh = @()
    if (Test-Path -LiteralPath $logsDir -PathType Container) {
        foreach ($f in @(Get-ChildItem -LiteralPath $logsDir -Filter "diag-*.txt" -ErrorAction SilentlyContinue)) {
            if (-not $beforeNames.ContainsKey($f.Name)) { $fresh += $f }
        }
        if ($fresh.Count -gt 0) {
            $diagTarget = @($fresh | Sort-Object LastWriteTime -Descending)[0]
        } else {
            $recent = @(Get-ChildItem -LiteralPath $logsDir -Filter "diag-*.txt" -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -ge $startTime.AddSeconds(-10) } |
                        Sort-Object LastWriteTime -Descending)
            if ($recent.Count -gt 0) { $diagTarget = $recent[0] }
        }
    }
    if ($diagTarget) {
        try { $diagText = [System.IO.File]::ReadAllText($diagTarget.FullName, [System.Text.Encoding]::UTF8) } catch { $diagText = "" }
        Note "A4 NEW REPORT PATH : $(Ascii $diagTarget.FullName)"
        Note "A4 NEW REPORT BYTES: $($diagText.Length)"
    } else {
        Note "A4 NEW REPORT PATH : (none found)"
    }
    Note "A4 DIAG EXIT CODE : $diagCode"
    if (-not [string]::IsNullOrEmpty($diagErr)) { Note "A4 LAUNCH ERROR : $diagErr" }

    # ASCII-safe excerpt of the UTF-8 diag report (Chinese stripped to '?').
    $shown = 0
    foreach ($l in (SplitLines $diagText)) {
        if ($shown -ge 40) { break }
        if ($l -match 'PySide2|MSVCP140|VCRUNTIME140|icuuc|7601|PortGuard|Qt |KB2999226|win7|Windows 7|UTF') {
            $c = (Ascii $l).Trim()
            if ($c.Length -gt 0) { Note "A4 DIAG> $c"; $shown++ }
        }
    }
    Note "A4 DIAG> (excerpt ends; glyph check-marks mapped to [OK]/[BAD])"

    if ($diagCode -eq 0) {
        V "A4_DIAG_EXIT_0" "PASS" "--diag --quiet returned exit code 0 (no blocking problem). AUTHORITATIVE GATE."
    } elseif ($diagCode -eq -999) {
        V "A4_DIAG_EXIT_0" "NEEDS-VISUAL" "could not obtain the diag exit code; inspect the report manually"
    } else {
        V "A4_DIAG_EXIT_0" "FAIL" "--diag --quiet returned exit code $diagCode"
    }

    if ($diagTarget -and $diagText.Length -gt 100) {
        V "A4_REPORT_WRITTEN" "PASS" "a new non-empty diag-*.txt appeared after this run"
    } else {
        V "A4_REPORT_WRITTEN" "FAIL" "no new non-empty diag-*.txt; report did not land"
    }

    if ($diagText -match 'Qt\s+\u7EBF\u8DEF\s*:\s*PySide2') {
        V "A4_QT_LINE_PYSIDE2" "PASS" "Qt line resolves to PySide2"
    } else {
        V "A4_QT_LINE_PYSIDE2" "FAIL" "Qt line is not PySide2 (Qt6 product cannot run on 2008R2)"
    }

    if ($diagText -match '\u7248\u672C\u5224\u5B9A\s*:\s*\u2713') {
        V "A4_VERSION_VERDICT_OK" "PASS" "version verdict carries the OK mark (7601 meets the Qt5 minimum)"
    } else {
        V "A4_VERSION_VERDICT_OK" "FAIL" "version verdict is not marked OK"
    }

    $dllNames = @("MSVCP140.dll","MSVCP140_1.dll","MSVCP140_2.dll","VCRUNTIME140.dll","VCRUNTIME140_1.dll")
    $dllBad = @()
    foreach ($n in $dllNames) {
        $pat = '(?m)^\s*\u2713\s+' + [regex]::Escape($n)
        if (-not [regex]::IsMatch($diagText, $pat)) { $dllBad += $n }
    }
    if ($dllBad.Count -eq 0) {
        V "A4_FIVE_VC_DLLS_OK" "PASS" "all 5 VC++ runtime DLLs are marked OK inside the bundle"
    } else {
        V "A4_FIVE_VC_DLLS_OK" "FAIL" "not OK: $(Ascii ([string]::Join(', ', $dllBad)))"
    }

    if ($diagText -match 'PySide2[^\r\n]*icuuc\.dll') {
        V "A4_QT5_ICUCC_NOTE" "PASS" "report states PySide2 (Qt5) does not depend on icuuc.dll"
    } else {
        V "A4_QT5_ICUCC_NOTE" "FAIL" "Qt5 icuuc note missing"
    }

    # Win7 / 2008R2 compatibility audit - this is the real structural gate.
    $hasLegacy = [regex]::IsMatch($diagText, '\u3010Win7 \u517C\u5BB9\u6027\u3011')
    $hasBlocker = [regex]::IsMatch($diagText, '\[win7-\u963B\u65AD\]|\[win7-\u8FD0\u884C\u5E93\]')
    Note "A4 Win7 compatibility section present : $hasLegacy ; blocker markers : $hasBlocker"
    if ($hasLegacy -and -not $hasBlocker) {
        V "A4_WIN7_AUDIT" "PASS" "Win7 compatibility section present with no blocker / redist-missing markers"
    } elseif (-not $hasLegacy) {
        V "A4_WIN7_AUDIT" "NEEDS-VISUAL" "Win7 compatibility section not found in report; read report manually"
    } else {
        V "A4_WIN7_AUDIT" "FAIL" "Win7 compatibility audit reported a blocker or missing redist"
    }

    # NOTE: two different spellings exist in core/diag.py:
    #   line text  = '?????' (shi)   -> \u4EA7\u7269\u5185\u7F3A\u5931
    #   conclusion = '?????' (shao) -> \u4EA7\u7269\u5185\u7F3A\u5C11
    $bundleMissing = [regex]::IsMatch($diagText, '\u4EA7\u7269\u5185\u7F3A\u5931|\u4EA7\u7269\u5185\u7F3A\u5C11')
    if ($bundleMissing) {
        V "A4_NO_BUNDLE_MISSING" "FAIL" "report says a runtime DLL is missing from the bundle"
    } else {
        V "A4_NO_BUNDLE_MISSING" "PASS" "no 'missing from bundle' text in report"
    }

    # '?????' is legitimately possible on a clean 2008R2 without KB2999226
    # (ucrtbase.dll). It is NOT a blocker on the Qt5 line; do not auto-FAIL.
    $sysMissing = [regex]::IsMatch($diagText, '\u7CFB\u7EDF\u4E5F\u7F3A\u5931')
    if (-not $sysMissing) {
        V "A4_NO_SYSTEM_MISSING" "PASS" "no 'system also missing' text in report"
    } elseif ($diagCode -eq 0) {
        V "A4_NO_SYSTEM_MISSING" "NEEDS-VISUAL" "system-also-missing text present but diag exit=0. On Qt5 this is usually ucrtbase.dll (2008R2 needs KB2999226). Human must record WHICH dll and confirm UCRT status. NOT an automatic FAIL."
    } else {
        V "A4_NO_SYSTEM_MISSING" "FAIL" "system-also-missing text present and diag exit code is not 0"
    }

    if ([regex]::IsMatch($diagText, '(?m)^\s*\u2717')) {
        V "A4_NO_BAD_MARKS" "FAIL" "report contains at least one BAD mark line"
    } else {
        V "A4_NO_BAD_MARKS" "PASS" "no BAD mark lines in report"
    }
    if (-not [regex]::IsMatch($diagText, '\u2713\s*\u672A\u53D1\u73B0\u963B\u585E\u6027\u95EE\u9898')) {
        V "A4_CONCLUSION_CLEAN" "NEEDS-VISUAL" "clean-conclusion line not found; read the report conclusion manually"
    } else {
        V "A4_CONCLUSION_CLEAN" "PASS" "report conclusion says no blocking problem found"
    }
    $crashNew = 0
    if (Test-Path -LiteralPath $logsDir -PathType Container) {
        foreach ($f in @(Get-ChildItem -LiteralPath $logsDir -Filter "crash-*.txt" -ErrorAction SilentlyContinue)) {
            if ($f.LastWriteTime -ge $startTime.AddSeconds(-30)) { $crashNew++ }
        }
    }
    Note "A4 new crash-*.txt files near this run : $crashNew"
    if ($crashNew -gt 0) {
        V "A4_NO_NEW_CRASH" "FAIL" "$crashNew new crash-*.txt appeared; the GUI path may have crashed"
    } else {
        V "A4_NO_NEW_CRASH" "PASS" "no new crash-*.txt near this run"
    }
}
Note "A4 NOTE: string checks above are ADVISORY. Exit code 0 is the gate."
Note "A4 NOTE: 'system also missing' is a false-FAIL trap on a clean 2008R2."

# A5 fonts
W "--- A5 FONT INVENTORY (C4 PRECONDITION) ---"
$fontFiles = @("msyhui.ttc","msyh.ttc","consola.ttf")
$fontRes = @{}
foreach ($f in $fontFiles) {
    $p = Join-Path $fontDir $f
    $fontRes[$f] = (Test-Path -LiteralPath $p -PathType Leaf)
    Note "A5 FILE $f : $($fontRes[$f])"
}
$regFontNames = @()
try {
    $fk = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" -ErrorAction SilentlyContinue
    if ($fk) { foreach ($pr in $fk.PSObject.Properties) { $regFontNames += [string]$pr.Name } }
} catch { }
$regYHUI = $false; $regYH = $false; $regCON = $false
foreach ($n in $regFontNames) {
    # Registry values may name TWO families at once, e.g.
    # "Microsoft YaHei & Microsoft YaHei UI (TrueType)". These must be
    # independent ifs, never if/elseif, or the plain family is missed.
    if ($n -match 'Microsoft YaHei UI') { $regYHUI = $true }
    if ($n -match 'Microsoft YaHei(?! UI)') { $regYH = $true }
    if ($n -match 'Consolas') { $regCON = $true }
}
Note "A5 REG family Microsoft YaHei UI registered : $regYHUI"
Note "A5 REG family Microsoft YaHei   registered : $regYH"
Note "A5 REG family Consolas          registered : $regCON"
Note "A5 NOTE: Qt resolves fonts by FAMILY NAME in the font DB, not by file name."
$yhuiFile = $fontRes["msyhui.ttc"]
$yhFile   = $fontRes["msyh.ttc"]
# A file/family disagreement is AMBIGUOUS, not a proven defect. On 2008R2
# the registry value naming is not verifiable from this dev machine.
$uiConflict = ($yhuiFile -ne $regYHUI)
$yhConflict = ($yhFile -ne $regYH)
if ((-not $yhuiFile) -and (-not $regYHUI)) {
    V "A5_MSYHUI_EXPECTED_ABSENT" "PASS" "no Microsoft YaHei UI font file and no registered family"
} elseif ($yhuiFile -and $regYHUI) {
    V "A5_MSYHUI_EXPECTED_ABSENT" "FAIL" "Microsoft YaHei UI is present: this is NOT a stock clean 2008R2; C4 premise invalid"
} else {
    V "A5_MSYHUI_EXPECTED_ABSENT" "NEEDS-VISUAL" "font file and registry family disagree; human must confirm the family Qt actually resolves"
}
if ($yhFile -and $regYH) {
    V "A5_MSYH_PRESENT" "PASS" "Microsoft YaHei fallback candidate is available"
} elseif ((-not $yhFile) -and (-not $regYH)) {
    V "A5_MSYH_PRESENT" "FAIL" "Microsoft YaHei font file and family both missing; C4 fallback target unavailable"
} else {
    V "A5_MSYH_PRESENT" "NEEDS-VISUAL" "font file and registry family disagree; confirm by eye"
}
if ($fontRes["consola.ttf"] -and $regCON) {
    V "A5_CONSOLA_PRESENT" "PASS" "Consolas available for monospace columns"
} else {
    V "A5_CONSOLA_PRESENT" "NEEDS-VISUAL" "Consolas file/family not both found; confirm monospace rendering by eye"
}
if ($uiConflict -or $yhConflict) {
    V "C4_PRECONDITION" "NEEDS-VISUAL" "font file/registry evidence disagrees; confirm the resolved family by eye before judging C4"
} elseif ((-not $yhuiFile) -and $yhFile) {
    V "C4_PRECONDITION" "PASS" "stock 2008R2 font fallback condition is met; C4 must now be done visually"
} else {
    V "C4_PRECONDITION" "FAIL" "font condition does not match a stock clean 2008R2; recheck A5 before C4"
}

# ============================================================ B. LOG SCAN
W "--- B. LOG SCAN AND VERSION STRINGS ---"
$logFiles = @()
if (Test-Path -LiteralPath $logsDir -PathType Container) {
    $logFiles = @(Get-ChildItem -LiteralPath $logsDir -Filter "portguard.log*" -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending)
}
Note "B0 portguard.log* files found : $($logFiles.Count)"
foreach ($f in @($logFiles | Select-Object -First 8)) {
    Note "B0 LOG FILE> $(Ascii $f.Name) bytes=$($f.Length) modified=$($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
}
$logText = ""
foreach ($f in $logFiles) {
    try { $logText += [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8) + [char]10 } catch { }
}

$markers = @(
    @{ Name = "TRACEBACK";          Pattern = 'Traceback' },
    @{ Name = "CRITICAL";           Pattern = 'CRITICAL' },
    @{ Name = "UI_START_FAILED";    Pattern = '\u754C\u9762\u542F\u52A8\u5931\u8D25' },
    @{ Name = "E2_PENDING_FAILED";  Pattern = '\u5199\u5165 pending \u8BB0\u5F55\u5931\u8D25' },
    @{ Name = "E2_NO_RULE_CREATED"; Pattern = '\u672A\u521B\u5EFA\u9632\u706B\u5899\u89C4\u5219' },
    @{ Name = "AUTO_BAN_FAILED";    Pattern = '\u81EA\u52A8\u5C01\u7981[^\r\n]*\u5931\u8D25' },
    @{ Name = "UNBANNED_STATUS";    Pattern = '\u5DF2\u89E3\u5C01' },
    @{ Name = "STARTUP_NORMAL";     Pattern = ('PortGuard\s+' + $verPat + '[^\r\n]*exe[^\r\n]*False') }
)
$markerCount = @{}
foreach ($mk in $markers) {
    $c = [regex]::Matches($logText, $mk.Pattern).Count
    $markerCount[$mk.Name] = $c
    Note "B0 MARKER $($mk.Name) = $c"
    if ($c -gt 0) {
        $mm = [regex]::Match($logText, $mk.Pattern)
        $sample = Ascii $mm.Value
        if ($sample.Length -gt 160) { $sample = $sample.Substring(0, 160) }
        Note "B0 SAMPLE $($mk.Name)> $sample"
    }
}
$fatal = $markerCount["TRACEBACK"] + $markerCount["CRITICAL"] + $markerCount["UI_START_FAILED"]
if ($logFiles.Count -eq 0) {
    V "B1_FATAL_MARKERS" "NEEDS-VISUAL" "no portguard.log* exists yet: this script never launches the GUI. Perform B1 manually first."
} elseif ($fatal -eq 0) {
    V "B1_FATAL_MARKERS" "PASS" "0 Traceback / CRITICAL / UI-start-failure markers across all portguard.log* files"
} else {
    V "B1_FATAL_MARKERS" "FAIL" "$fatal fatal markers found in portguard.log*"
}
# A startup line from an EARLIER run looks identical to one from this run.
# This collector never launches the GUI, so it CANNOT bind a log line to the
# human's operation window. Never auto-PASS B1 on a matching line alone.
$newestLog = $null
foreach ($lf in $logFiles) {
    if ($null -eq $newestLog -or $lf.LastWriteTime -gt $newestLog.LastWriteTime) { $newestLog = $lf }
}
if ($null -eq $newestLog) {
    V "B1_WINDOW_PROOF" "NEEDS-VISUAL" "no portguard.log* found. Human must perform B1 first (launch GUI as standard user) and record the operation window."
} else {
    Note "B1 NEWEST LOG > $(Ascii $newestLog.Name) modified=$($newestLog.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) checked=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    V "B1_WINDOW_PROOF" "NEEDS-VISUAL" "a startup line from a PREVIOUS run is NOT proof. Human must confirm its timestamp falls inside THIS operation window and record the window in PG196_EVIDENCE_INDEX.txt. Script never launches the GUI."
}
if ([string]::IsNullOrEmpty($version)) {
    V "B1_STARTUP_LINE" "NEEDS-VISUAL" "version could not be parsed from the zip filename; a historical startup line from another build is NOT accepted as this package's proof"
} elseif ($markerCount["STARTUP_NORMAL"] -gt 0) {
    V "B1_STARTUP_LINE" "NEEDS-VISUAL" "candidate startup line for $versionLabel found, but a line from a PREVIOUS run looks identical. NOT auto-PASSed: human must bind its timestamp to THIS operation window (see B1_WINDOW_PROOF)."
} else {
    V "B1_STARTUP_LINE" "NEEDS-VISUAL" "no positive startup line matching version $versionLabel. Absence of error strings is NOT proof the GUI started. Confirm B1 by eye."
}

# B2 version strings
$verTxt = ""
$chgVer = ""
$exeVer = ""
if (Test-Path -LiteralPath $verPath -PathType Leaf) {
    $verTxt = [System.IO.File]::ReadAllText($verPath, [System.Text.Encoding]::UTF8).Trim()
    $verTxt = Ascii $verTxt
}
if (Test-Path -LiteralPath $chgPath -PathType Leaf) {
    $ct = [System.IO.File]::ReadAllText($chgPath, [System.Text.Encoding]::UTF8)
    # CHANGELOG prose quotes historical versions (e.g. "this log has shipped
    # since v1.9.2"). Taking the FIRST vX.Y.Z anywhere in the text reports a
    # historical version as the current one and causes a FALSE FAIL on a
    # perfectly good package. Only a version HEADING at the start of a line
    # declares the current version; older headings are kept below as history.
    $mh = [regex]::Match($ct, '(?m)^\s*(v[0-9]+\.[0-9]+\.[0-9]+)')
    if ($mh.Success) { $chgVer = $mh.Groups[1].Value }
    $allv = @()
    foreach ($vm in [regex]::Matches($ct, 'v[0-9]+\.[0-9]+\.[0-9]+')) {
        if ($allv -notcontains $vm.Value) { $allv += $vm.Value }
    }
    Note "B2 CHANGELOG v-token count : $($allv.Count) distinct (historical versions in prose/older headings are ignored); heading=$(Ascii $chgVer)"
}
if (Test-Path -LiteralPath $exePath -PathType Leaf) {
    try { $exeVer = [string](Get-Item -LiteralPath $exePath).VersionInfo.FileVersion } catch { $exeVer = "" }
}
Note "B2 EXPECTED VERSION : $versionLabel (parsed from zip filename)"
Note "B2 VERSION.txt      : $verTxt"
Note "B2 CHANGELOG heading: $chgVer (first LINE-START version heading; prose quotes history)"
Note "B2 ZIP file name    : $(Ascii $zipName)"
Note "B2 EXE FileVersion  : $(Ascii $exeVer)"
$verTxtOk = $false; $chgOk = $false; $exeOk = $false
if (-not [string]::IsNullOrEmpty($version)) {
    $vp = [regex]::Escape($version)
    if ($verTxt -match $vp) { $verTxtOk = $true }
    if ($chgVer -eq ("v" + $version)) { $chgOk = $true }
    if ($exeVer -match $vp) { $exeOk = $true }
}
if ([string]::IsNullOrEmpty($version)) {
    V "B2_FILE_VERSIONS" "NEEDS-VISUAL" "no version parsed from zip filename; cannot compare the four sources"
} elseif ($verTxtOk -and $chgOk -and $exeOk) {
    V "B2_FILE_VERSIONS" "PASS" "VERSION.txt / CHANGELOG heading / zip name / exe FileVersion all agree on $version"
} elseif ([string]::IsNullOrEmpty($exeVer) -or [string]::IsNullOrEmpty($verTxt)) {
    V "B2_FILE_VERSIONS" "NEEDS-VISUAL" "one or more version sources unreadable; confirm on the About page"
} else {
    V "B2_FILE_VERSIONS" "FAIL" "version mismatch: expected $version; VERSION.txt=$verTxt CHANGELOG_HEADING=$chgVer EXE=$exeVer"
}
V "B2_ABOUT_PAGE" "NEEDS-VISUAL" "About page version must be read by a human"
V "B3_ALL_9_PAGES" "NEEDS-VISUAL" "9 stack pages (incl. Overview, Bans, Rules); switch each by hand"
V "B4_PERMISSION_PANEL" "NEEDS-VISUAL" "permission panel wording must be read by a human"

# ============================================================ C. VISUAL
W "--- C. VISUAL ACCEPTANCE (HUMAN ONLY) ---"
V "C1_MONITOR_100PCT" "NEEDS-VISUAL" "1360x860 @100% DPI; worst-case columns must not show ellipsis"
V "C2_MONITOR_125PCT" "NEEDS-VISUAL" "1200x800 @100% and 1360x860 @125% DPI; re-logon after DPI change"
V "C3_OTHER_TABLES" "NEEDS-VISUAL" "events / ban suggestions / ban records worst-case columns"
V "C4_FONT_FALLBACK" "NEEDS-VISUAL" "MANDATORY. QSS fallback is silent: judge by actual non-truncated columns, not by font file names"
V "C5_TOOLTIP_FULLTEXT" "NEEDS-VISUAL" "hover long text; tooltip must reveal the full string"
Note "C4 NOTE: gui/theme.py:134 lists 4 font families. Absence of msyhui.ttc does NOT prove Qt picked Microsoft YaHei."

# ============================================================ D/E/F NETSH
W "--- D/E/F/G NETSH READ-ONLY INVENTORY ---"
$rRules = Run "netsh.exe" @("advfirewall", "firewall", "show", "rule", "name=all")
$rCtrl  = Run "netsh.exe" @("advfirewall", "show", "allprofiles")
$ctrlOk = ($rCtrl.Code -eq 0 -and $rCtrl.Text.Length -gt 50)
$ruleOk = ($rRules.Code -eq 0 -and $rRules.Text.Length -gt 50)
Note "NETSH show rule name=all : code=$($rRules.Code) bytes=$($rRules.Text.Length)"
Note "NETSH positive control show allprofiles : code=$($rCtrl.Code) bytes=$($rCtrl.Text.Length) OK=$ctrlOk"
Note "NETSH NOTE: netsh output is localized. Rule names and paths are ASCII and are extracted from raw text, never from labels."

$ruleNames = @()
foreach ($mm in [regex]::Matches($rRules.Text, 'PortGuard_(?:Block|Allow)_[A-Za-z0-9_.\-]+')) {
    $n = $mm.Value
    if ($ruleNames -notcontains $n) { $ruleNames += $n }
}
$blockNames = @()
$allowNames = @()
foreach ($n in $ruleNames) {
    if ($n -match '^PortGuard_Block_') { $blockNames += $n }
    if ($n -match '^PortGuard_Allow_') { $allowNames += $n }
}
Note "RULE COUNT PortGuard_Block_* : $($blockNames.Count)"
Note "RULE COUNT PortGuard_Allow_* : $($allowNames.Count)"
Note "RULE NAMES BLOCK : $(Ascii ([string]::Join(', ', $blockNames)))"
Note "RULE NAMES ALLOW : $(Ascii ([string]::Join(', ', $allowNames)))"

if (-not $ctrlOk -or -not $ruleOk) {
    V "NETSH_POSITIVE_CONTROL" "FAIL" "netsh did not return a usable non-empty result; a '0 rules' finding would be a FALSE PASS"
} else {
    V "NETSH_POSITIVE_CONTROL" "PASS" "netsh alive; a zero-rule finding is now trustworthy"
}
$netshTrusted = ($ctrlOk -and $ruleOk)

# D3 / D2 / test-ip match
if (-not $netshTrusted) {
    V "D3_BLOCK_RULE_EXISTS" "NEEDS-VISUAL" "netsh control failed; cannot trust the rule inventory"
} elseif ($blockNames.Count -ge 1) {
    V "D3_BLOCK_RULE_EXISTS" "PASS" "$($blockNames.Count) PortGuard_Block_* rule(s) present (existence only; verify Enabled/Action/RemoteIP manually)"
} else {
    V "D3_BLOCK_RULE_EXISTS" "NEEDS-VISUAL" "0 block rules. D2 may not have been performed yet; do NOT auto-PASS and do NOT auto-FAIL."
}
if ([string]::IsNullOrEmpty($TestIp)) {
    V "D3_MATCH_TEST_IP" "NEEDS-VISUAL" "supply the D2 test IPv4 as argument 3 to check the exact rule name"
} else {
    $tok = $TestIp.Replace(':', '-').Replace('/', '-').Replace(' ', '')
    $tok = -join ($tok.ToCharArray() | Where-Object { [char]::IsLetterOrDigit($_) -or $_ -eq '-' -or $_ -eq '.' -or $_ -eq '_' })
    $wantName = "PortGuard_Block_" + $tok
    Note "D3 EXPECTED RULE NAME for test IP : $(Ascii $wantName)"
    if ($blockNames -contains $wantName) {
        V "D3_MATCH_TEST_IP" "PASS" "exact rule name for the D2 test IP is present"
    } else {
        V "D3_MATCH_TEST_IP" "FAIL" "exact rule name for the D2 test IP is absent"
    }
}
V "D1_UAC_AND_TOPBAR" "NEEDS-VISUAL" "UAC prompt and top-bar permission state after start-as-admin.bat"
V "D2_NEW_ACTIVE_RECORD" "NEEDS-VISUAL" "exactly one NEW active ban record, not a stale one"
V "D4_EXPIRED_AND_RULE_GONE" "NEEDS-VISUAL" "UI 'unbanned' status + exact rule-name diff showing removal"
V "D5_MANUAL_UNBLOCK" "NEEDS-VISUAL" "manual unblock removes the rule within a bounded time"

# E1 / E2 / E3 baseline and set diff
W "--- E1/E3 RULE-NAME BASELINE AND SET DIFF ---"
if ($Mode -eq "SAVEBASE") {
    if (-not $netshTrusted) {
        V "E1_BASELINE_SAVED" "FAIL" "netsh control failed; refusing to save an untrustworthy baseline"
    } else {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("# PortGuard rule-name baseline (ASCII); package version = $versionLabel")
        [void]$sb.AppendLine("# saved $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') mode=SAVEBASE")
        [void]$sb.AppendLine("# netsh control OK=$ctrlOk rule bytes=$($rRules.Text.Length)")
        foreach ($n in ($ruleNames | Sort-Object)) { [void]$sb.AppendLine($n) }
        [System.IO.File]::WriteAllText($basePath, $sb.ToString(), [System.Text.Encoding]::ASCII)
        V "E1_BASELINE_SAVED" "PASS" "$($ruleNames.Count) exact rule names written to $BASE_NAME"
    }
}
$baseNames = @()
$baseExists = (Test-Path -LiteralPath $basePath -PathType Leaf)
if ($baseExists) {
    $bt = [System.IO.File]::ReadAllText($basePath, [System.Text.Encoding]::ASCII)
    foreach ($l in (SplitLines $bt)) {
        $t = ([string]$l).Trim()
        if ($t -match '^PortGuard_(?:Block|Allow)_[A-Za-z0-9_.\-]+$') {
            if ($baseNames -notcontains $t) { $baseNames += $t }
        }
    }
}
Note "E1 baseline file exists : $baseExists ; baseline rule names : $($baseNames.Count)"
$newRules = @(); $removedRules = @()
if ($baseExists -and $netshTrusted) {
    foreach ($n in $ruleNames) { if ($baseNames -notcontains $n) { $newRules += $n } }
    foreach ($n in $baseNames) { if ($ruleNames -notcontains $n) { $removedRules += $n } }
    Note "E3 NEW RULES (exact set diff)     : $(Ascii ([string]::Join(', ', $newRules)))"
    Note "E3 REMOVED RULES (exact set diff) : $(Ascii ([string]::Join(', ', $removedRules)))"
    Note "E3 NOTE: a set diff, not a count. Equal counts can still hide remove+add."
} else {
    Note "E3 set diff NOT computed: baseline missing or netsh untrusted."
}

$e2Fired = ($markerCount["E2_PENDING_FAILED"] -gt 0 -and $markerCount["E2_NO_RULE_CREATED"] -gt 0)
if (-not $e2Fired) {
    V "E2_FAILURE_INJECTION_FIRED" "NEEDS-VISUAL" "no 'write pending failed' + 'no rule created' marker in portguard.log*. If the injection did not fire, E3 is vacuous. Also verify the audit row via Settings > Audit > Export CSV (result=fail)."
} else {
    V "E2_FAILURE_INJECTION_FIRED" "PASS" "write-failure markers present in portguard.log*"
}
if (-not ($baseExists -and $netshTrusted)) {
    V "E3_NO_ORPHAN_RULES" "NEEDS-VISUAL" "run SAVEBASE before E2, then FULL/DIFF after E2; baseline missing or netsh untrusted"
} elseif (-not $e2Fired) {
    V "E3_NO_ORPHAN_RULES" "NEEDS-VISUAL" "E2 failure was not observed; 'no new rules' would be a false PASS"
} else {
    $newBlock = @()
    foreach ($n in $newRules) { if ($n -match '^PortGuard_Block_') { $newBlock += $n } }
    if ($newBlock.Count -eq 0) {
        V "E3_NO_ORPHAN_RULES" "PASS" "E2 fired and exact-name diff shows 0 new PortGuard_Block_* rules"
    } else {
        V "E3_NO_ORPHAN_RULES" "FAIL" "orphan rule(s) created: $(Ascii ([string]::Join(', ', $newBlock)))"
    }
}
if ($baseExists -and $netshTrusted -and $removedRules.Count -gt 0) {
    V "D4_RULE_REMOVED_EVIDENCE" "PASS" "exact-name diff shows $($removedRules.Count) removed rule(s)"
} else {
    V "D4_RULE_REMOVED_EVIDENCE" "NEEDS-VISUAL" "no removal evidence yet; UI 'unbanned' status still needs a human"
}
V "D4_UI_UNBANNED_STATUS" "NEEDS-VISUAL" "ban record page status must be read by a human"
V "E4_NO_GHOST_RECORD" "NEEDS-VISUAL" "clear filters/pages in the ban list; confirm DB and firewall agree"
V "E2_DB_PATH_NOTE" "NEEDS-VISUAL" "on the delivery package the DB is $(Ascii $dbPath) - NOT data/portguard.db"

# F2 logging path
W "--- F2 NETSH LOGGING PATH ---"
$rLog = Run "netsh.exe" @("advfirewall", "show", "allprofiles", "logging")
$logCmdOk = ($rLog.Code -eq 0 -and $rLog.Text.Length -gt 50)
Note "F2 netsh show allprofiles logging : code=$($rLog.Code) bytes=$($rLog.Text.Length)"
$logPaths = @()
# Do NOT de-duplicate: netsh prints one FileName line per profile
# (Domain / Private / Public). Three identical custom paths must stay
# three lines, otherwise the "all 3 profiles" check becomes a false red.
foreach ($mm in [regex]::Matches($rLog.Text, '(?:[A-Za-z]:\\|%[A-Za-z]+%\\)[^\r\n]*?\.log')) {
    $p = ([string]$mm.Value).Trim().Trim('"').Trim()
    $logPaths += $p
}
Note "F2 path lines found (expect 3 profiles, no de-dup) : $($logPaths.Count)"
$i = 0
foreach ($p in $logPaths) { $i++; Note "F2 PATH[$i] : $(Ascii $p)" }
foreach ($l in (SplitLines $rLog.Text)) {
    if ($l -match '\.log|pfirewall|FileName') { Note "F2 RAW> $((Ascii $l).Trim())" }
}
$anyDefault = $false
foreach ($p in $logPaths) {
    if ($p -match '(?i)System32\\LogFiles\\Firewall\\pfirewall\.log') { $anyDefault = $true }
}
Note "F2 default path keyword detected : $anyDefault"
if (-not $logCmdOk) {
    V "F2_NETSH_CMD" "FAIL" "netsh logging query failed or returned empty output; cannot conclude anything"
} else {
    V "F2_NETSH_CMD" "PASS" "netsh logging query returned a usable non-empty result"
}
if ($logPaths.Count -eq 0) {
    V "F2_PATH_EXTRACTION" "NEEDS-VISUAL" "no .log path value found. Output is localized; do NOT search for the literal 'FileName'. Extract path values from raw text."
} elseif ($anyDefault) {
    V "F2_NOT_DEFAULT_PATH" "FAIL" "at least one profile still points at the default pfirewall.log (M5 regression)"
} else {
    V "F2_NOT_DEFAULT_PATH" "PASS" "no profile shows the default pfirewall.log"
}
$expectedNorm = NormalizePath $ExpectedLogPath
if ([string]::IsNullOrEmpty($expectedNorm)) {
    V "F2_ALL_PROFILES_CUSTOM" "NEEDS-VISUAL" "pass the exact F1 custom path as argument 2 to compare; a toast alone is not evidence"
} elseif ($logPaths.Count -lt 3) {
    V "F2_ALL_PROFILES_CUSTOM" "NEEDS-VISUAL" "only $($logPaths.Count) path line(s) found; expected 3 profiles. Localized output or partial config; do NOT auto-PASS."
} else {
    $allMatch = $true
    foreach ($p in $logPaths) { if ((NormalizePath $p) -ne $expectedNorm) { $allMatch = $false } }
    if ($allMatch) {
        V "F2_ALL_PROFILES_CUSTOM" "PASS" "all 3 profile path values equal the F1 custom path"
    } else {
        V "F2_ALL_PROFILES_CUSTOM" "FAIL" "not all 3 profile paths equal the F1 custom path"
    }
}
Note "F2 NOTE: core/win_fwlog.py:509-523 shows the Chinese label is '??????', not 'FileName'."
V "F1_TOAST_AND_PATH" "NEEDS-VISUAL" "record the exact typed path and the success toast"
V "F3_FRESH_LOG_ROWS" "NEEDS-VISUAL" "require NEW parsed rows in the operation window, not just a bigger log file"
V "F4_HOT_SWITCH_BACK" "NEEDS-VISUAL" "re-run F2+F3 with default path; PID must be unchanged (no restart)"

# G1 residual inventory (current-state snapshot)
W "--- G1 RESIDUAL RULE SNAPSHOT (CURRENT STATE) ---"
if (-not $netshTrusted) {
    V "G1_NO_RESIDUAL" "NEEDS-VISUAL" "netsh control failed; zero rules would be a false PASS"
} elseif ($ruleNames.Count -eq 0) {
    V "G1_NO_RESIDUAL" "PASS" "0 PortGuard rules in current inventory (re-run FULL after the G1 uninstall)"
} else {
    V "G1_NO_RESIDUAL" "FAIL" "$($ruleNames.Count) PortGuard rule(s) still present in current inventory"
}
V "G2_USER_DATA_DIR" "NEEDS-VISUAL" "list %APPDATA%\PortGuard BEFORE any deletion; export all evidence first"
V "G3_SNAPSHOT_ROLLBACK" "NEEDS-VISUAL" "LAST step only. Export evidence out of the VM before rollback."

# ============================================================ SUMMARY
W "======================================================================"
W "SUMMARY"
$nPass = 0; $nFail = 0; $nVis = 0
foreach ($s in $script:States) {
    if ($s -eq "PASS") { $nPass++ } elseif ($s -eq "FAIL") { $nFail++ } else { $nVis++ }
}
W "PASS=$nPass FAIL=$nFail NEEDS-VISUAL=$nVis TOTAL=$($script:States.Count)"
W "FAIL items must be fixed before the section 5 signature page."
W "NEEDS-VISUAL items MUST be filled by a human on the 2008R2 desktop."
W "This report is EVIDENCE ONLY. It does not sign the release and does not"
W "replace the 30-item checklist, the screenshots, or the final verdict."
W "======================================================================"

$text = $script:Rpt.ToString()
[System.IO.File]::WriteAllText($reportPath, $text, [System.Text.Encoding]::ASCII)
Write-Host "Report written (ASCII): verify_2008r2_report.txt"
exit 0
