# package.ps1 — winiptables packaging script
# Bundles build artifacts, WinDivert runtime, and MSVC CRT into a standalone
# directory that can be deployed to a clean machine without any dependencies.
# Optionally builds an Inno Setup installer from the packaged files.
# Automatically detects the installed Visual Studio version (VS2022/VS2026).
#
# Usage:
#   .\package.ps1                          # Build Release then package (default)
#   .\package.ps1 -Config Debug            # Build Debug then package
#   .\package.ps1 -OutDir my_dist          # Custom output directory
#   .\package.ps1 -NoBuild                 # Skip build, package existing artifacts
#   .\package.ps1 -Rebuild                 # Clean build directory before building
#   .\package.ps1 -WithTests               # Also build unit tests
#   .\package.ps1 -MakeInstaller           # Also produce an Inno Setup installer EXE
#   .\package.ps1 -Rebuild -MakeInstaller  # Full rebuild + package + installer
#   .\package.ps1 -VsVersion 2022          # Force Visual Studio 2022
#   .\package.ps1 -VsVersion 2026          # Force Visual Studio 2026
param(
    [string]$Config    = "Release",
    [string]$OutDir    = "dist\winiptables",
    [switch]$NoBuild,
    [switch]$Rebuild,
    [switch]$WithTests,
    [switch]$MakeInstaller,
    # Force a specific VS version: 2022 or 2026 (auto-detect if omitted)
    [ValidateSet("", "2022", "2026")]
    [string]$VsVersion = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Version ───────────────────────────────────────────────────────────────────

$VersionFile = Join-Path $PSScriptRoot "version.txt"
if (-not (Test-Path $VersionFile)) { Write-Error "version.txt not found: $VersionFile" }
$AppVersion = (Get-Content $VersionFile -Raw).Trim()
if ($AppVersion -notmatch '^\d+\.\d+\.\d+') {
    Write-Error "Invalid version format in version.txt: '$AppVersion' (expected X.Y.Z)"
}
Write-Host "Version: $AppVersion" -ForegroundColor Gray

# ── Detect Visual Studio ──────────────────────────────────────────────────────
# Supports VS2022 (17.x) and VS2026 (18.x), any edition.
# Uses vswhere when available, falls back to filesystem scan.

function Find-VsInstall {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    }

    if (Test-Path $vswhere) {
        $json = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -format json 2>$null | ConvertFrom-Json
        if ($json -and $json.Count -gt 0) {
            $major = [int]($json[0].installationVersion -split '\.')[0]
            return [PSCustomObject]@{
                InstallPath  = $json[0].installationPath
                DisplayName  = $json[0].displayName
                Version      = $json[0].installationVersion
                MajorVersion = $major
            }
        }
    }

    # Fallback: scan known paths for VS2026 (18) then VS2022 (17)
    $editions = @("Enterprise", "Professional", "Community", "BuildTools", "Insiders", "Preview")
    foreach ($major in @(18, 17)) {
        foreach ($ed in $editions) {
            $root = "C:\Program Files\Microsoft Visual Studio\$major\$ed"
            if (Test-Path "$root\VC\Tools\MSVC") {
                return [PSCustomObject]@{
                    InstallPath  = $root
                    DisplayName  = "Visual Studio $major $ed"
                    Version      = "$major.0"
                    MajorVersion = $major
                }
            }
        }
    }
    return $null
}

$VsInstall = Find-VsInstall
if (-not $VsInstall) { Write-Error "No Visual Studio with C++ tools found." }

# If -VsVersion is specified, verify the detected version matches
if ($VsVersion -ne "") {
    $wantedMajor = @{ "2022" = 17; "2026" = 18 }[$VsVersion]
    if ($VsInstall.MajorVersion -ne $wantedMajor) {
        # Auto-detect returned a different version — try to find the requested one directly
        $editions = @("Enterprise", "Professional", "Community", "BuildTools", "Insiders", "Preview")
        $found = $null
        foreach ($ed in $editions) {
            $root = "C:\Program Files\Microsoft Visual Studio\$wantedMajor\$ed"
            if (Test-Path "$root\VC\Tools\MSVC") {
                $found = [PSCustomObject]@{
                    InstallPath  = $root
                    DisplayName  = "Visual Studio $wantedMajor $ed"
                    Version      = "$wantedMajor.0"
                    MajorVersion = $wantedMajor
                }
                break
            }
        }
        if (-not $found) {
            Write-Error "Visual Studio $VsVersion (major $wantedMajor) not found. Remove -VsVersion to auto-detect."
        }
        $VsInstall = $found
    }
}
Write-Host "VS:      $($VsInstall.DisplayName) ($($VsInstall.Version))" -ForegroundColor Gray

# Map major version to CMake generator name
$VsGeneratorMap = @{
    18 = "Visual Studio 18 2026"
    17 = "Visual Studio 17 2022"
}
$VsGenerator = $VsGeneratorMap[$VsInstall.MajorVersion]
if (-not $VsGenerator) {
    Write-Warning "Unknown VS major version $($VsInstall.MajorVersion), defaulting to VS 17 2022"
    $VsGenerator = "Visual Studio 17 2022"
}

# Locate MSVC Redist root
$VsRedist = $null
$RedistRoot = Join-Path $VsInstall.InstallPath "VC\Redist\MSVC"
if (Test-Path $RedistRoot) { $VsRedist = $RedistRoot }

# ── Paths ─────────────────────────────────────────────────────────────────────

$ScriptDir = $PSScriptRoot
$BuildDir  = Join-Path $ScriptDir "build"
$BinDir    = Join-Path $ScriptDir "build\bin\$Config"
$WinDivert = Join-Path $ScriptDir "third_party\windivert\lib\x64"
$Dest      = Join-Path $ScriptDir $OutDir

# ── Step 1: Build ─────────────────────────────────────────────────────────────

if ($NoBuild) {
    Write-Host "[1/5] Skipping build (-NoBuild)" -ForegroundColor Yellow
} else {
    Write-Host "[1/5] Building ($Config) with $VsGenerator..." -ForegroundColor Cyan

    if ($Rebuild -and (Test-Path $BuildDir)) {
        Write-Host "  Cleaning build directory (-Rebuild)..." -ForegroundColor Gray
        Remove-Item $BuildDir -Recurse -Force
    }

    if (-not (Test-Path $BuildDir)) {
        Write-Host "  Running cmake configure..." -ForegroundColor Gray
        $cmakeArgs = @("-S", $ScriptDir, "-B", $BuildDir, "-G", $VsGenerator, "-A", "x64")
        if ($WithTests) { $cmakeArgs += "-DBUILD_TESTS=ON" }
        cmake @cmakeArgs
        if ($LASTEXITCODE -ne 0) { Write-Error "cmake configure failed" }
    }

    if ($WithTests) { Write-Host "  Unit tests enabled (-WithTests)" -ForegroundColor Gray }

    cmake --build $BuildDir --config $Config
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed" }
}

# ── Step 2: Verify artifacts ──────────────────────────────────────────────────

Write-Host "[2/5] Verifying build artifacts..." -ForegroundColor Cyan

foreach ($bin in @("winiptables.exe", "winiptables-svc.exe")) {
    $path = Join-Path $BinDir $bin
    if (-not (Test-Path $path)) {
        Write-Error "Missing artifact: $path`nRun without -NoBuild or build manually first."
    }
}

# ── Step 3: Create output directory ───────────────────────────────────────────

Write-Host "[3/5] Creating output directory: $Dest" -ForegroundColor Cyan

if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
New-Item -ItemType Directory -Path $Dest | Out-Null

# ── Step 4: Copy program files ────────────────────────────────────────────────

Write-Host "[4/5] Copying program files..." -ForegroundColor Cyan

Copy-Item (Join-Path $BinDir "winiptables.exe")     $Dest
Copy-Item (Join-Path $BinDir "winiptables-svc.exe") $Dest
Write-Host "  + winiptables.exe"
Write-Host "  + winiptables-svc.exe"

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

# WinDivert runtime
foreach ($f in @("WinDivert.dll", "WinDivert64.sys")) {
    $src = Join-Path $WinDivert $f
    if (-not (Test-Path $src)) { Write-Error "Missing WinDivert file: $src" }
    Copy-Item $src $Dest
    Write-Host "  + $f"
}

# ── Step 5: Copy MSVC CRT ─────────────────────────────────────────────────────

Write-Host "[5/5] Copying MSVC CRT runtime..." -ForegroundColor Cyan

if (-not $VsRedist) {
    Write-Warning "  Skipping CRT copy: Redist directory not found under $($VsInstall.InstallPath)"
} else {
    $RedistVersion = Get-ChildItem $VsRedist |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+' } |
        Sort-Object Name -Descending |
        Select-Object -First 1

    if (-not $RedistVersion) {
        Write-Warning "  No versioned Redist subdirectory found under: $VsRedist"
    } else {
        $CrtDir = Get-ChildItem (Join-Path $RedistVersion.FullName "x64") |
            Where-Object { $_.Name -match 'Microsoft\.VC\d+\.CRT' } |
            Select-Object -First 1

        if (-not $CrtDir) {
            Write-Warning "  CRT directory not found under: $(Join-Path $RedistVersion.FullName 'x64')"
        } else {
            Write-Host "  Using Redist: $($RedistVersion.Name) / $($CrtDir.Name)" -ForegroundColor Gray

            foreach ($dll in @("vcruntime140.dll","vcruntime140_1.dll","msvcp140.dll",
                                "msvcp140_1.dll","msvcp140_2.dll","concrt140.dll")) {
                $src = Join-Path $CrtDir.FullName $dll
                if (Test-Path $src) {
                    Copy-Item $src $Dest
                    Write-Host "  + $dll"
                } else {
                    Write-Warning "  Skipped (not found): $dll"
                }
            }
        }
    }

    # Universal CRT
    foreach ($p in @("C:\Windows\System32\ucrtbase.dll",
                      "C:\Program Files (x86)\Windows Kits\10\Redist\ucrt\DLLs\x64\ucrtbase.dll")) {
        if (Test-Path $p) {
            Copy-Item $p $Dest
            Write-Host "  + ucrtbase.dll (from $p)"
            break
        }
    }
}

# ── Generate README ───────────────────────────────────────────────────────────

@"
winiptables $AppVersion $Config Package
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
"@ | Out-File -FilePath (Join-Path $Dest "README.txt") -Encoding UTF8

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Package complete." -ForegroundColor Green
Write-Host "Output: $Dest" -ForegroundColor Green
Write-Host ""
Get-ChildItem $Dest | Format-Table Name, Length -AutoSize

# ── Step 6: Build Inno Setup installer (optional) ─────────────────────────────

if ($MakeInstaller) {
    Write-Host "[6/6] Building installer..." -ForegroundColor Cyan

    $IssFile = Join-Path $ScriptDir "installer\winiptables.iss"
    if (-not (Test-Path $IssFile)) { Write-Error "Inno Setup script not found: $IssFile" }

    # Locate ISCC.exe
    $IsccCmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($IsccCmd) {
        $IsccPath = $IsccCmd.Source
    } else {
        $IsccPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
        if (-not (Test-Path $IsccPath)) {
            Write-Error "ISCC.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isinfo.php"
        }
    }
    Write-Host "  Using ISCC: $IsccPath" -ForegroundColor Gray

    & $IsccPath /DAppVersion="$AppVersion" $IssFile
    if ($LASTEXITCODE -ne 0) { Write-Error "Inno Setup compile failed" }

    Write-Host ""
    Write-Host "Installer ready: $(Join-Path $ScriptDir "dist\winiptables-$AppVersion-setup.exe")" -ForegroundColor Green
}
