# run-tests.ps1 — Build and run all unit tests, then report results.
#
# Usage:
#   .\run-tests.ps1                    # Build Debug + run all tests
#   .\run-tests.ps1 -Config Release    # Build Release + run all tests
#   .\run-tests.ps1 -NoBuild           # Skip build, run existing test binaries
#   .\run-tests.ps1 -Filter "rule*"    # Run only tests whose name matches the pattern
#   .\run-tests.ps1 -OutputDir reports # Write XML results to custom directory

param(
    [string]$Config    = "Debug",
    [string]$Filter    = "*",
    [string]$OutputDir = "test-results",
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$BuildDir  = Join-Path $ScriptDir "build"
$BinDir    = Join-Path $BuildDir "bin\$Config"
$ResultDir = Join-Path $ScriptDir $OutputDir

# ── Step 1: Build ─────────────────────────────────────────────────────────────

if ($NoBuild) {
    Write-Host "[1/3] Skipping build (-NoBuild)" -ForegroundColor Yellow
} else {
    Write-Host "[1/3] Building tests ($Config)..." -ForegroundColor Cyan

    if (-not (Test-Path $BuildDir)) {
        Write-Host "  Running cmake configure..." -ForegroundColor Gray
        cmake -S $ScriptDir -B $BuildDir -DBUILD_TESTS=ON
        if ($LASTEXITCODE -ne 0) { Write-Error "cmake configure failed" }
    } else {
        # Re-run configure to ensure BUILD_TESTS=ON is set
        cmake -S $ScriptDir -B $BuildDir -DBUILD_TESTS=ON | Out-Null
    }

    cmake --build $BuildDir --config $Config
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed" }
}

# ── Step 2: Discover test binaries ────────────────────────────────────────────

Write-Host "[2/3] Discovering test binaries in: $BinDir" -ForegroundColor Cyan

$TestExes = Get-ChildItem $BinDir -Filter "test_*.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like $Filter -or $Filter -eq "*" }

if (-not $TestExes) {
    Write-Error "No test binaries found in $BinDir. Build with -DBUILD_TESTS=ON first."
}

Write-Host "  Found $($TestExes.Count) test suite(s):" -ForegroundColor Gray
$TestExes | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }

# ── Step 3: Run tests ─────────────────────────────────────────────────────────

Write-Host "[3/3] Running tests..." -ForegroundColor Cyan

if (-not (Test-Path $ResultDir)) {
    New-Item -ItemType Directory -Path $ResultDir | Out-Null
}

$TotalPassed  = 0
$TotalFailed  = 0
$TotalSkipped = 0
$FailedSuites = @()

foreach ($exe in $TestExes) {
    $suiteName  = $exe.BaseName
    $xmlOutput  = Join-Path $ResultDir "$suiteName.xml"

    Write-Host ""
    Write-Host "  Running: $suiteName" -ForegroundColor White

    # Run with GTest XML output; capture stderr separately to avoid
    # PowerShell treating native exe stderr as a terminating error.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $exe.FullName
    $psi.Arguments              = "--gtest_output=xml:$xmlOutput"
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $exitCode = $proc.ExitCode

    # Print stdout with colorized GTest lines
    foreach ($line in ($stdout -split "`r?`n")) {
        if ($line -match '^\[  PASSED  \]') {
            Write-Host "  $line" -ForegroundColor Green
        } elseif ($line -match '^\[  FAILED  \]') {
            Write-Host "  $line" -ForegroundColor Red
        } elseif ($line -match '^\[ RUN      \]') {
            Write-Host "  $line" -ForegroundColor DarkCyan
        } elseif ($line -match '^\[       OK \]') {
            Write-Host "  $line" -ForegroundColor Green
        } elseif ($line -match '^\[  SKIPPED \]') {
            Write-Host "  $line" -ForegroundColor Yellow
        } elseif ($line -ne '') {
            Write-Host "  $line"
        }
    }
    # Print stderr (expected for some tests, e.g. error-path tests)
    if ($stderr.Trim() -ne '') {
        foreach ($line in ($stderr -split "`r?`n")) {
            if ($line -ne '') { Write-Host "  [stderr] $line" -ForegroundColor DarkGray }
        }
    }

    # Parse XML for counts
    if (Test-Path $xmlOutput) {
        [xml]$xml = Get-Content $xmlOutput
        $suite   = $xml.testsuites
        $total   = [int]$suite.tests
        $failed  = [int]$suite.failures + [int]$suite.errors
        # 'skipped' attribute may not exist in all GTest XML versions
        Set-StrictMode -Off
        $skipped = if ($suite.skipped) { [int]$suite.skipped } else { 0 }
        Set-StrictMode -Version Latest
        $passed  = $total - $failed - $skipped

        $TotalPassed  += $passed
        $TotalFailed  += $failed
        $TotalSkipped += $skipped
    }

    if ($exitCode -ne 0) {
        $FailedSuites += $suiteName
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Test Results Summary" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host ("  Passed  : {0,4}" -f $TotalPassed)  -ForegroundColor Green
Write-Host ("  Failed  : {0,4}" -f $TotalFailed)  -ForegroundColor $(if ($TotalFailed -gt 0) { "Red" } else { "Green" })
Write-Host ("  Skipped : {0,4}" -f $TotalSkipped) -ForegroundColor Yellow
Write-Host ("  Suites  : {0,4}" -f $TestExes.Count)
Write-Host "  XML reports: $ResultDir"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

if ($FailedSuites.Count -gt 0) {
    Write-Host ""
    Write-Host "  Failed suites:" -ForegroundColor Red
    $FailedSuites | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host ""
    exit 1
} else {
    Write-Host ""
    Write-Host "  All tests passed." -ForegroundColor Green
    Write-Host ""
    exit 0
}
