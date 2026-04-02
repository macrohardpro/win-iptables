# winiptables

[中文文档](README.zh.md) | English

A Windows port of Linux iptables, built on [WinDivert](https://reqrypt.org/windivert.html).  
Manage network traffic on Windows using the same `iptables` syntax you already know.

---

## Features

- `iptables`-compatible CLI — `-A`, `-I`, `-D`, `-L`, `-F`, `-Z`, `-N`, `-X`, `-P`, `-E`
- `filter`, `nat`, `mangle` tables with standard built-in chains
- Match conditions: `-p`, `-s`, `-d`, `-i`, `-o`, `--sport`, `--dport`, `--tcp-flags`, `--icmp-type`, `-m multiport`, `-m state`
- Targets: `ACCEPT`, `DROP`, `REJECT`, `RETURN`, `LOG`, `JUMP`, `MASQUERADE`, `DNAT`, `SNAT`
- Rule persistence (`iptables-save` / `iptables-restore` compatible format)
- Per-rule packet/byte counters (`-L -v`)
- Stateful connection tracking (`-m state --state NEW,ESTABLISHED,...`)
- Runs as a Windows Service — starts automatically with the system
- CLI communicates with the service over a Named Pipe

---

## Architecture

```
winiptables.exe (CLI)
    └── Named Pipe ──► winiptables-svc.exe (Service)
                            ├── CommandDispatcher → RuleStore
                            ├── TablePipeline (raw→mangle→nat→filter)
                            ├── RuleEngine
                            └── PacketCapture (WinDivert)
```

---

## Requirements

- Windows 10 / Server 2016 or later (x64)
- Administrator privileges (WinDivert requires kernel driver access)
- Visual Studio 2022 / 2026 with "Desktop development with C++" workload
- CMake ≥ 3.20

All third-party dependencies (`WinDivert`, `GoogleTest`) are bundled under `third_party/` — no internet access needed to build.

---

## Quick Start

### 1. Build

```powershell
# Configure
cmake -S . -B build -G "Visual Studio 18 2026" -A x64

# Build Release
cmake --build build --config Release
```

Or use the packaging script which builds and bundles everything automatically:

```powershell
.\package.ps1
```

### 2. Install the service

> All commands below require an **Administrator** PowerShell prompt.

```powershell
# Install and register the Windows service
.\build\bin\Release\winiptables-svc.exe install

# Start the service
.\build\bin\Release\winiptables.exe service start
```

### 3. Add rules

```powershell
# Allow inbound TCP on port 80
winiptables.exe -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow inbound TCP on port 443
winiptables.exe -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop all other inbound traffic
winiptables.exe -P INPUT DROP

# List rules
winiptables.exe -L -n -v
```

### 4. Save and restore rules

```powershell
# Save current ruleset to file
winiptables.exe save > rules.v4

# Restore on next boot (or after a flush)
winiptables.exe restore < rules.v4
```

### 5. Stop and uninstall

```powershell
winiptables.exe service stop
winiptables-svc.exe uninstall
```

---

## Console Mode (no service install)

Useful for testing and debugging — runs the packet filter directly in the terminal:

```powershell
# Requires Administrator
.\build\bin\Debug\winiptables-svc.exe --console
```

Press `Ctrl+C` to stop.

---

## Deploy to another machine

Use `package.ps1` to bundle the executables, WinDivert runtime, and MSVC CRT into a single directory that runs on a clean machine with no dependencies:

```powershell
.\package.ps1                  # Release build + package
.\package.ps1 -Config Debug    # Debug build + package
.\package.ps1 -NoBuild         # Package existing build artifacts
```

Output goes to `dist\winiptables\`. Copy the entire folder to the target machine and follow the steps in [Quick Start](#quick-start).

---

## Run Tests

```powershell
# Build and run all unit tests (Debug)
.\run-tests.ps1

# Release build
.\run-tests.ps1 -Config Release

# Skip build, run existing binaries
.\run-tests.ps1 -NoBuild

# Filter by suite name
.\run-tests.ps1 -Filter "test_rule*"
```

XML reports are written to `test-results/`.

---

## Project Structure

```
winiptables/
├── include/winiptables/    # Public headers (model, interfaces, components)
├── src/
│   ├── core/               # Shared static library (rule engine, packet capture, ...)
│   ├── cli/                # CLI executable (winiptables.exe)
│   └── service/            # Service executable (winiptables-svc.exe)
├── tests/                  # GoogleTest unit tests
├── third_party/            # Bundled dependencies (WinDivert, GoogleTest)
├── cmake/                  # CMake find modules
├── BUILD.md                # Detailed build instructions
├── package.ps1             # Build + package script
└── run-tests.ps1           # Build + test script
```

See [BUILD.md](BUILD.md) for detailed build, test, and deployment instructions.

---

## License

MIT
