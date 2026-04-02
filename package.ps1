# package.ps1 — winiptables packaging script
# Bundles build artifacts, WinDivert runtime, and MSVC CRT into a standalone
# directory that can be deployed to a clean machine without any dependencies.
#
# Usage:
#   .\package.ps1                      # Build Release then package (default)
#   .\package.ps1 -Config Debug        # Build Debug then package
#   .\package.ps1 -OutDir my_dist      # Custom output directory
#   .\package.ps1 -NoBuild             # Skip build, package existing artifacts
#   .\package.ps1 -WithTests           # Also build unit tests (excluded by default)
#   .\package.ps1 -NoBuild -WithTests  # Skip build but include existing test binaries

param(
    [string]$Config    = "Release",
    [string]$OutDir    = "dist\winiptables",
    [switch]$NoBuild,
    [switch]$WithTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Paths ─────────────────────────────────────────────────────────────────────

$ScriptDir  = $PSScriptRoot
$BuildDir   = Join-Path $ScriptDir "build"
$BinDir     = Join-Path $ScriptDir "build\bin\$Config"
$WinDivert  = Join-Path $ScriptDir "third_party\windivert\lib\x64"
$VsRedist   = "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Redist\MSVC"
$Dest       = Join-Path $ScriptDir $OutDir

# ── Step 1: Build ─────────────────────────────────────────────────────────────

if ($NoBuild) {
    Write-Host "[1/5] Skipping build (-NoBuild)" -ForegroundColor Yellow
} else {
    Write-Host "[1/5] Building ($Config)..." -ForegroundColor Cyan

    if (-not (Test-Path $BuildDir)) {
        Write-Host "  Running cmake configure..." -ForegroundColor Gray
        $cmakeArgs = @("-S", $ScriptDir, "-B", $BuildDir)
        if ($WithTests) { $cmakeArgs += "-DBUILD_TESTS=ON" }
        cmake @cmakeArgs
        if ($LASTEXITCODE -ne 0) { Write-Error "cmake configure failed" }
    }

    if ($WithTests) {
        Write-Host "  Unit tests enabled (-WithTests)" -ForegroundColor Gray
    }

    cmake --build $BuildDir --config $Config
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed" }
}

# ── Step 2: Verify artifacts ──────────────────────────────────────────────────

Write-Host "[2/5] Verifying build artifacts..." -ForegroundColor Cyan

$RequiredBins = @("winiptables.exe", "winiptables-svc.exe")
foreach ($bin in $RequiredBins) {
    $path = Join-Path $BinDir $bin
    if (-not (Test-Path $path)) {
        Write-Error "Missing artifact: $path`nRun without -NoBuild or build manually first."
    }
}

# ── Step 3: Create output directory ───────────────────────────────────────────

Write-Host "[3/5] Creating output directory: $Dest" -ForegroundColor Cyan

if (Test-Path $Dest) {
    Remove-Item $Dest -Recurse -Force
}
New-Item -ItemType Directory -Path $Dest | Out-Null

# ── Step 4: Copy program files ────────────────────────────────────────────────

Write-Host "[4/5] Copying program files..." -ForegroundColor Cyan

# Main executables (exe only, no pdb/lib)
Copy-Item (Join-Path $BinDir "winiptables.exe")     $Dest
Copy-Item (Join-Path $BinDir "winiptables-svc.exe") $Dest
Write-Host "  + winiptables.exe"
Write-Host "  + winiptables-svc.exe"

# Optional: test binaries
if ($WithTests) {
    $TestBins = Get-ChildItem $BinDir -Filter "test_*.exe" -ErrorAction SilentlyContinue
    if ($TestBins) {
        $TestDest = Join-Path $Dest "tests"
        New-Item -ItemType Directory -Path $TestDest | Out-Null
        foreach ($t in $TestBins) {
            Copy-Item $t.FullName $TestDest
            Write-Host "  + tests\$($t.Name)"
        }
    } else {
        Write-Warning "  No test binaries found in $BinDir"
    }
}

# WinDivert runtime (driver + DLL)
$WinDivertFiles = @("WinDivert.dll", "WinDivert64.sys")
foreach ($f in $WinDivertFiles) {
    $src = Join-Path $WinDivert $f
    if (-not (Test-Path $src)) {
        Write-Error "Missing WinDivert file: $src"
    }
    Copy-Item $src $Dest
    Write-Host "  + $f"
}

# ── Step 5: Copy MSVC CRT ─────────────────────────────────────────────────────

Write-Host "[5/5] Copying MSVC CRT runtime..." -ForegroundColor Cyan

# Find the latest Redist version directory
$RedistVersion = Get-ChildItem $VsRedist |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
    Sort-Object Name -Descending |
    Select-Object -First 1

if (-not $RedistVersion) {
    Write-Error "MSVC Redist directory not found: $VsRedist"
}

# Find VC CRT directory (supports VS2022/VS2026)
$CrtDir = Get-ChildItem (Join-Path $RedistVersion.FullName "x64") |
    Where-Object { $_.Name -match 'Microsoft\.VC\d+\.CRT' } |
    Select-Object -First 1

if (-not $CrtDir) {
    Write-Error "CRT directory not found under: $(Join-Path $RedistVersion.FullName 'x64')"
}

Write-Host "  Using Redist: $($RedistVersion.Name) / $($CrtDir.Name)"

$CrtDlls = @(
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "concrt140.dll"
)

foreach ($dll in $CrtDlls) {
    $src = Join-Path $CrtDir.FullName $dll
    if (Test-Path $src) {
        Copy-Item $src $Dest
        Write-Host "  + $dll"
    } else {
        Write-Warning "  Skipped (not found): $dll"
    }
}

# Universal CRT (ucrtbase.dll) from Windows SDK or System32
$UcrtPaths = @(
    "C:\Windows\System32\ucrtbase.dll",
    "C:\Program Files (x86)\Windows Kits\10\Redist\ucrt\DLLs\x64\ucrtbase.dll"
)
foreach ($p in $UcrtPaths) {
    if (Test-Path $p) {
        Copy-Item $p $Dest
        Write-Host "  + ucrtbase.dll (from $p)"
        break
    }
}

# ── Generate README ───────────────────────────────────────────────────────────

$ReadmeContent = @"
winiptables $Config Release Package
=====================================

Files
-----
  winiptables.exe      - CLI tool
  winiptables-svc.exe  - Background Windows service
  WinDivert.dll        - WinDivert user-mode library
  WinDivert64.sys      - WinDivert kernel driver
  vcruntime140*.dll    - MSVC runtime
  msvcp140*.dll        - MSVC C++ standard library
  concrt140.dll        - MSVC concurrency runtime
  ucrtbase.dll         - Universal CRT
  tests\               - Unit test binaries (only present when built with -WithTests)

Usage (requires Administrator privileges)
------------------------------------------
1. Install the service:
   winiptables-svc.exe install

2. Start the service:
   winiptables.exe service start

3. Example rules:
   winiptables.exe -A INPUT -p tcp --dport 80 -j ACCEPT
   winiptables.exe -L

4. Stop and uninstall:
   winiptables.exe service stop
   winiptables-svc.exe uninstall

Console mode (debug, no service install required):
   winiptables-svc.exe --console
"@

$ReadmeContent | Out-File -FilePath (Join-Path $Dest "README.txt") -Encoding UTF8

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Package complete." -ForegroundColor Green
Write-Host "Output: $Dest" -ForegroundColor Green
Write-Host ""

Get-ChildItem $Dest | Format-Table Name, Length -AutoSize
