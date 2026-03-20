# Vettaiyan EDR — Setup & Installation Guide

Complete guide to deploy Vettaiyan EDR from build output.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Windows 10/11 x64 (build 17763+) |
| **Privilege** | Administrator (elevated PowerShell for all steps) |
| **Test Signing** | Required for unsigned kernel drivers |
| **Visual Studio** | Only needed for building — not for deployment |
| **Windows App SDK** | Required for the VettaiyanNode dashboard |

---

## 1. Prepare the Deployment Directory

Create a clean deployment folder and copy all required files from the build output.

```powershell
# Create deployment directory
$deploy = "C:\VettaiyanEDR"
New-Item -ItemType Directory -Path $deploy -Force
New-Item -ItemType Directory -Path "$deploy\rules" -Force
New-Item -ItemType Directory -Path "$deploy\assets" -Force
```

### Copy from build output (`x64\Debug\`)

```powershell
$build = "D:\vettaiyan\x64\Debug"

# Agent service executable
Copy-Item "$build\VettaiyanAgent.exe" $deploy

# Kernel driver files
Copy-Item "$build\VettaiyanDriver.sys" $deploy
Copy-Item "$build\VettaiyanDriver.inf" $deploy
Copy-Item "$build\VettaiyanDriver.cer" $deploy

# Filesystem filter driver files
Copy-Item "$build\VettaiyanFilter.sys" $deploy
Copy-Item "$build\VettaiyanFilter.inf" $deploy
Copy-Item "$build\VettaiyanFilter.cer" $deploy
```

### Copy runtime DLLs (from vcpkg)

The agent links against these DLLs at runtime. They **must** be in the same directory as `VettaiyanAgent.exe`:

```powershell
$vcpkgBin = "D:\vettaiyan\vcpkg_installed\x64-windows\bin"

Copy-Item "$vcpkgBin\magic-1.dll"       $deploy
Copy-Item "$vcpkgBin\sqlite3.dll"       $deploy
Copy-Item "$vcpkgBin\libcrypto-3-x64.dll" $deploy
Copy-Item "$vcpkgBin\libssl-3-x64.dll"  $deploy
Copy-Item "$vcpkgBin\tre.dll"           $deploy
Copy-Item "$vcpkgBin\getopt.dll"        $deploy
Copy-Item "$vcpkgBin\legacy.dll"        $deploy
```

### Copy YARA rules and magic database

```powershell
# Compiled YARA rules
Copy-Item "D:\vettaiyan\VettaiyanAgent\rules\vettaiyan.rules" "$deploy\rules\"

# libmagic database (required for MIME type detection)
Copy-Item "D:\vettaiyan\vcpkg_installed\x64-windows\share\libmagic\misc\magic.mgc" $deploy

# Agent assets (icons for notifications)
Copy-Item "D:\vettaiyan\VettaiyanAgent\assets\*" "$deploy\assets\" -Recurse
```

### Final directory structure

```
C:\VettaiyanEDR\
├── VettaiyanAgent.exe          # Agent service
├── VettaiyanDriver.sys         # Kernel process/thread/registry monitor
├── VettaiyanDriver.inf
├── VettaiyanDriver.cer
├── VettaiyanFilter.sys         # Filesystem minifilter
├── VettaiyanFilter.inf
├── VettaiyanFilter.cer
├── magic-1.dll                 # libmagic runtime
├── sqlite3.dll                 # SQLite runtime
├── libcrypto-3-x64.dll         # OpenSSL runtime
├── libssl-3-x64.dll
├── tre.dll                     # regex library
├── getopt.dll
├── legacy.dll
├── magic.mgc                   # MIME type database
├── rules/
│   └── vettaiyan.rules         # Compiled YARA rules
└── assets/
    ├── VettaiyanLogo.ico
    └── VettaiyanLogo.png
```

---

## 2. Enable Test Signing (Required for Unsigned Drivers)

The kernel drivers are self-signed. Windows must be in test-signing mode to load them.

```powershell
# Enable test signing (requires reboot)
bcdedit /set testsigning on

# Reboot
Restart-Computer
```

> After reboot you'll see a "Test Mode" watermark on the desktop. This is normal.

To disable later:
```powershell
bcdedit /set testsigning off
```

---

## 3. Install the Kernel Driver (VettaiyanDriver)

This driver monitors process creation, thread activity, image loads, registry operations, and handle operations.

### Install the test certificate

```powershell
certutil -f -addstore TrustedPublisher "C:\VettaiyanEDR\VettaiyanDriver.cer"
certutil -f -addstore Root "C:\VettaiyanEDR\VettaiyanDriver.cer"
```

> Use `-f` to force store creation if the `TrustedPublisher` store doesn't exist yet.

### Create the driver service and install

**Option A: Using sc.exe (simplest for development)**

```powershell
# Copy .sys to the drivers directory
Copy-Item "C:\VettaiyanEDR\VettaiyanDriver.sys" "C:\Windows\System32\drivers\" -Force

# Create a kernel driver service
sc.exe create VettaiyanDriver type= kernel binPath= "C:\Windows\System32\drivers\VettaiyanDriver.sys" start= demand

# Start the driver
sc.exe start VettaiyanDriver
```

**Option B: Using devcon.exe (WDK tools — proper PnP install)**

```powershell
# Find devcon.exe from your WDK installation
$devcon = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Tools" -Recurse -Filter "devcon.exe" |
    Where-Object { $_.DirectoryName -match "x64" } | Select-Object -First 1 -ExpandProperty FullName

# Install driver with hardware ID from the INF
& $devcon install "C:\VettaiyanEDR\VettaiyanDriver.inf" Root\VettaiyanDriver
```

**Option C: Using pnputil (requires signed .cat file)**

If you need pnputil, first sign the catalog file:

```powershell
# Generate catalog from INF (run from VS Developer Command Prompt)
Inf2Cat /driver:"C:\VettaiyanEDR" /os:10_x64 /verbose

# Sign with the test certificate
$cert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match "WDKTestCert" }
signtool sign /v /s Root /n "WDKTestCert" /t http://timestamp.digicert.com "C:\VettaiyanEDR\VettaiyanDriver.cat"

# Now pnputil will accept it
pnputil /add-driver "C:\VettaiyanEDR\VettaiyanDriver.inf" /install
```

> **Note:** `pnputil` rejects unsigned INFs. Options A or B are recommended for development.

### Verify the driver loaded

```powershell
sc.exe query VettaiyanDriver
# State should be RUNNING

# Check kernel debug output (via DebugView or WinDbg):
# You should see: "[ VettaiyanDriver ] Driver loaded successfully"
```

### Start/stop the driver manually

```powershell
sc.exe start VettaiyanDriver
sc.exe stop VettaiyanDriver
```

### Uninstall the driver

```powershell
sc.exe stop VettaiyanDriver
pnputil /remove-device /deviceid Root\VettaiyanDriver
sc.exe delete VettaiyanDriver
```

---

## 4. Install the Filesystem Filter Driver (VettaiyanFilter)

This minifilter monitors file creation, writes, deletes, and renames.

### Install the test certificate

```powershell
certutil -f -addstore TrustedPublisher "C:\VettaiyanEDR\VettaiyanFilter.cer"
certutil -f -addstore Root "C:\VettaiyanEDR\VettaiyanFilter.cer"
```

### Install the minifilter

```powershell
# Copy driver to system32\drivers
Copy-Item "C:\VettaiyanEDR\VettaiyanFilter.sys" "C:\Windows\System32\drivers\"

# Install using the INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 C:\VettaiyanEDR\VettaiyanFilter.inf
```

### Verify the filter loaded

```powershell
fltmc

# You should see VettaiyanFilter in the list with altitude 369100
```

### Start/stop the filter manually

```powershell
fltmc load VettaiyanFilter
fltmc unload VettaiyanFilter
```

### Uninstall the filter

```powershell
fltmc unload VettaiyanFilter
sc.exe delete VettaiyanFilter
Remove-Item "C:\Windows\System32\drivers\VettaiyanFilter.sys" -Force
```

---

## 5. Install the Agent Service (VettaiyanAgent)

The agent is the core user-mode service that:
- Receives events from both kernel drivers
- Runs YARA scans on files
- Performs behavioral detection (MITRE ATT&CK)
- Consumes ETW telemetry (network, DNS, PowerShell)
- Handles response actions (kill, quarantine, isolate)

### Delete stale service entry (if exists)

```powershell
sc.exe stop Vettaiyan 2>$null
sc.exe delete Vettaiyan 2>$null

# Also clear the registry hive if it persists
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\Vettaiyan" -Recurse -Force -ErrorAction SilentlyContinue
```

### Create and start the service

```powershell
sc.exe create Vettaiyan binPath= "C:\VettaiyanEDR\VettaiyanAgent.exe" start= demand
```

> **Important:** There MUST be a space after `binPath=` and after `start=`. This is `sc.exe` syntax.

```powershell
sc.exe start Vettaiyan
```

### Verify the service is running

```powershell
sc.exe query Vettaiyan
# State should be RUNNING

# Check the named pipes exist
Test-Path '\\.\pipe\VettaiyanScanner'    # Scan request pipe
Test-Path '\\.\pipe\VettaiyanCommand'    # Command/response pipe
```

### Check the agent log

The agent writes a log file next to its executable:

```powershell
Get-Content "C:\VettaiyanEDR\VettaiyanLogFile.log" -Tail 50
```

You should see the full startup sequence:
```
[ VettaiyanAgent ] ====== SERVICE STARTING ======
[ VettaiyanAgent ] YARA engine initialized
[ VettaiyanAgent ] Event receiver init...
[ VettaiyanAgent ] ====== ALL SYSTEMS OPERATIONAL ======
```

### Stop and remove the service

```powershell
sc.exe stop Vettaiyan
sc.exe delete Vettaiyan
```

---

## 6. Install the Dashboard (VettaiyanNode)

The WinUI 3 dashboard is a packaged MSIX application.

### Option A: Run from Visual Studio (Development)

1. Open `VettaiyanEDR.sln` in Visual Studio
2. Set `VettaiyanNode` as startup project
3. Press F5 — it deploys via MSIX automatically

### Option B: Deploy the MSIX package

```powershell
# From the build output, find the .msix or use the loose files:
$appDir = "D:\vettaiyan\x64\Debug"

# Register the app from loose layout
Add-AppxPackage -Register "$appDir\AppxManifest.xml" -ForceApplicationShutdown
```

### Option C: Run unpackaged (if available)

If built as unpackaged, just run `VettaiyanNode.exe` from the output directory.

### Database Path

The UI reads scan results and telemetry from the SQLite database created by the agent:

```
C:\VettaiyanEDR\data.db
```

> **Note:** Update the database path in `VettaiyanNode\Common\Global.cs` if your agent is deployed to a different directory than `C:\Users\monis\source\repos\VettaiyanEDR\x64\Debug\`.

---

## 7. Add Right-Click Context Menu (Scan with Vettaiyan)

The agent registers this automatically on start, but you can also do it manually:

```powershell
# Add context menu entry
reg add "HKLM\Software\Classes\*\shell\ScanWithVettaiyan" /ve /d "Scan with Vettaiyan (YARA)" /f

reg add "HKLM\Software\Classes\*\shell\ScanWithVettaiyan" /v Icon /d "C:\VettaiyanEDR\assets\VettaiyanLogo.ico" /f

reg add "HKLM\Software\Classes\*\shell\ScanWithVettaiyan\command" /ve /d "cmd.exe /c echo %1 | C:\VettaiyanEDR\VettaiyanAgent.exe" /f
```

To remove:
```powershell
reg delete "HKLM\Software\Classes\*\shell\ScanWithVettaiyan" /f
```

---

## 8. Verify Full Stack

Run these checks to confirm everything is operational:

```powershell
Write-Host "=== Vettaiyan EDR Health Check ===" -ForegroundColor Cyan

# 1. Kernel driver
$drv = sc.exe query VettaiyanDriver 2>&1
if ($drv -match "RUNNING") { Write-Host "[OK] Kernel Driver: RUNNING" -ForegroundColor Green }
else { Write-Host "[!!] Kernel Driver: NOT RUNNING" -ForegroundColor Red }

# 2. Filesystem filter
$flt = fltmc 2>&1
if ($flt -match "VettaiyanFilter") { Write-Host "[OK] Filter Driver: LOADED" -ForegroundColor Green }
else { Write-Host "[!!] Filter Driver: NOT LOADED" -ForegroundColor Red }

# 3. Agent service
$svc = sc.exe query Vettaiyan 2>&1
if ($svc -match "RUNNING") { Write-Host "[OK] Agent Service: RUNNING" -ForegroundColor Green }
else { Write-Host "[!!] Agent Service: NOT RUNNING" -ForegroundColor Red }

# 4. Named pipes
if (Test-Path '\\.\pipe\VettaiyanScanner') { Write-Host "[OK] Scanner Pipe: ACTIVE" -ForegroundColor Green }
else { Write-Host "[!!] Scanner Pipe: NOT FOUND" -ForegroundColor Red }

if (Test-Path '\\.\pipe\VettaiyanCommand') { Write-Host "[OK] Command Pipe: ACTIVE" -ForegroundColor Green }
else { Write-Host "[!!] Command Pipe: NOT FOUND" -ForegroundColor Red }

# 5. Database
if (Test-Path "C:\VettaiyanEDR\data.db") { Write-Host "[OK] Database: EXISTS" -ForegroundColor Green }
else { Write-Host "[!!] Database: NOT FOUND (created on first scan)" -ForegroundColor Yellow }

# 6. YARA rules
if (Test-Path "C:\VettaiyanEDR\rules\vettaiyan.rules") { Write-Host "[OK] YARA Rules: FOUND" -ForegroundColor Green }
else { Write-Host "[!!] YARA Rules: MISSING" -ForegroundColor Red }

Write-Host "=================================" -ForegroundColor Cyan
```

---

## 9. Compiling Custom YARA Rules

To add your own detection rules:

### On Linux/WSL

```bash
# Install yarac
sudo apt install yara

# Compile all .yar files into a single compiled rules file
find rules/ -name "*.yar" -print0 | xargs -0 yarac rules/vettaiyan.rules
```

### On Windows (using yarac from vcpkg)

```powershell
$yarac = "D:\vettaiyan\vcpkg_installed\x64-windows\tools\yara\yarac.exe"
& $yarac "D:\vettaiyan\rules\my_rule.yar" "C:\VettaiyanEDR\rules\vettaiyan.rules"
```

After updating rules, restart the agent:
```powershell
sc.exe stop Vettaiyan; sc.exe start Vettaiyan
```

---

## 10. Troubleshooting

### Service fails with error 1053 (timeout)

This means the agent didn't call `SetServiceStatus(SERVICE_RUNNING)` fast enough.

**Causes:**
1. **Missing DLLs** — Ensure all vcpkg runtime DLLs are in the same folder as `VettaiyanAgent.exe`
2. **Missing YARA rules** — The `rules\vettaiyan.rules` file must exist relative to the EXE
3. **Missing magic.mgc** — The `magic.mgc` file must exist relative to the EXE
4. **Access denied** — Run the service as LocalSystem (default) or an admin account

**Debug steps:**
```powershell
# Check for missing DLLs (run from the deploy directory)
cd C:\VettaiyanEDR

# Try running the EXE directly (will fail with SCM error but reveals DLL issues)
.\VettaiyanAgent.exe

# If you see "The code execution cannot proceed because xxx.dll was not found",
# copy that DLL from vcpkg_installed\x64-windows\bin\

# Check the agent log
Get-Content "C:\VettaiyanEDR\VettaiyanLogFile.log"

# Check Windows Event Log for service failures
Get-WinEvent -LogName System -MaxEvents 20 | Where-Object { $_.Message -match "Vettaiyan" }
```

### Driver fails to load

```powershell
# Check test signing is enabled
bcdedit | Select-String "testsigning"
# Should show: testsigning  Yes

# Check certificate is trusted
certutil -store TrustedPublisher | Select-String "Vettaiyan"

# Check driver status via sc
sc.exe query VettaiyanDriver

# Check DriverSign output (kernel debug log)
# Use DebugView (SysInternals) with "Capture Kernel" enabled
```

### Filter fails to load

```powershell
# Check registered filters
fltmc

# Force load with verbose output
fltmc load VettaiyanFilter
# Error 0x80070002 = .sys file not in system32\drivers

# Verify .sys is in the right place
Test-Path "C:\Windows\System32\drivers\VettaiyanFilter.sys"
```

### Dashboard can't connect to agent

The UI connects to the agent via named pipes. Verify:

```powershell
# Check pipes exist
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "Vettaiyan" }

# Check the database path in Global.cs matches the agent's actual location
# The agent creates data.db next to VettaiyanAgent.exe
```

---

## Architecture Reference

```
┌──────────────────────────────────────────────────────┐
│                    KERNEL MODE                        │
│                                                      │
│  VettaiyanDriver.sys    VettaiyanFilter.sys           │
│  ├ Process callbacks    ├ File create/write/delete     │
│  ├ Thread callbacks     └ FltCommunicationPort ──┐    │
│  ├ Image load                                    │    │
│  ├ Registry callbacks                            │    │
│  └ IOCTL ring buffer ──────────────────────┐     │    │
│                                            │     │    │
└────────────────────────────────────────────┼─────┼────┘
                                             │     │
┌────────────────────────────────────────────┼─────┼────┐
│                    USER MODE               │     │    │
│                                            ▼     ▼    │
│  VettaiyanAgent.exe (Windows Service)                  │
│  ├ EventReceiver ← IOCTL + FilterPort                  │
│  ├ ProcessTracker (process tree)                       │
│  ├ BehaviorEngine (MITRE ATT&CK rules)                │
│  ├ EtwConsumer (network/DNS/PowerShell)                │
│  ├ YaraScanner (file scanning)                         │
│  ├ ResponseEngine (kill/quarantine/isolate)            │
│  ├ TelemetryDb (SQLite: data.db)                       │
│  ├─ \\.\pipe\VettaiyanScanner (scan requests)         │
│  └─ \\.\pipe\VettaiyanCommand (response commands)     │
│         ▲              ▲                               │
│         │              │                               │
│  VettaiyanNode.exe (WinUI 3 Dashboard)                 │
│  ├ Dashboard  ├ Timeline   ├ Behavioral Alerts         │
│  ├ Threats    ├ Response   ├ Scan    ├ Settings         │
│  └ Protocol: vettaiyan://scan?target=...               │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## Quick Reference

| Action | Command |
|---|---|
| Start agent | `sc.exe start Vettaiyan` |
| Stop agent | `sc.exe stop Vettaiyan` |
| Start driver | `sc.exe start VettaiyanDriver` |
| Load filter | `fltmc load VettaiyanFilter` |
| Unload filter | `fltmc unload VettaiyanFilter` |
| Check pipes | `Test-Path '\\.\pipe\VettaiyanScanner'` |
| View log | `Get-Content C:\VettaiyanEDR\VettaiyanLogFile.log -Tail 50` |
| Health check | Run the PowerShell script from Section 8 |


---

```bash
docker run -d --name elastic -p 9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" elasticsearch:8.12.0
Invoke-RestMethod -Uri "http://192.168.1.8:9200/vettaiyan-events" -Method Delete
cd D:\vettaiyan\elk
.\setup-index.ps1
```