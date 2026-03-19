@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VettaiyanEDR -- Management Console
::  Agent + Kernel Driver + Minifilter + Web Dashboard
::  Run as Administrator from the build output directory
:: ============================================================

:: Determine script directory (where VettaiyanAgent.exe lives)
set "EDR_DIR=%~dp0"
set "EDR_DIR=%EDR_DIR:~0,-1%"

:: Component paths
set "AGENT_EXE=%EDR_DIR%\VettaiyanAgent.exe"
set "DRIVER_SYS=%EDR_DIR%\VettaiyanDriver\VettaiyanDriver.sys"
set "DRIVER_CER=%EDR_DIR%\VettaiyanDriver.cer"
set "FILTER_SYS=%EDR_DIR%\VettaiyanFilter\VettaiyanFilter.sys"
set "FILTER_CER=%EDR_DIR%\VettaiyanFilter.cer"
set "WEB_DIR=%EDR_DIR%\web"
set "DASHBOARD_URL=http://127.0.0.1:9630"

:: Service / driver names
set "AGENT_SVC=Vettaiyan"
set "DRIVER_SVC=VettaiyanDriver"
set "FILTER_SVC=VettaiyanFilter"

:: ---- Check admin ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] This script must be run as Administrator.
    echo          Right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: ---- Menu ----
:menu
cls
echo.
echo  ========================================================
echo   VettaiyanEDR Management Console
echo  ========================================================
echo   Directory : %EDR_DIR%
echo   Dashboard : %DASHBOARD_URL%
echo  ========================================================
echo.
echo   1.  Install ALL ^& Open Dashboard
echo   2.  Uninstall ALL
echo   3.  Status
echo  --------------------------------------------------------
echo   4.  Start ALL       5.  Stop ALL
echo   6.  Open Dashboard
echo  --------------------------------------------------------
echo   7.  Install  Driver     8.  Uninstall Driver
echo   9.  Install  Filter     10. Uninstall Filter
echo   11. Install  Agent      12. Uninstall Agent
echo  --------------------------------------------------------
echo   13. Check prerequisites
echo   14. View Agent log
echo   15. Test agent launch (diagnostic)
echo   0.  Exit
echo.
set /p choice="  Select option: "

if "%choice%"=="1"  goto install_all
if "%choice%"=="2"  goto uninstall_all
if "%choice%"=="3"  goto status_all
if "%choice%"=="4"  goto start_all
if "%choice%"=="5"  goto stop_all
if "%choice%"=="6"  goto open_dashboard
if "%choice%"=="7"  goto install_driver
if "%choice%"=="8"  goto uninstall_driver
if "%choice%"=="9"  goto install_filter
if "%choice%"=="10" goto uninstall_filter
if "%choice%"=="11" goto install_agent
if "%choice%"=="12" goto uninstall_agent
if "%choice%"=="13" goto check_prereqs
if "%choice%"=="14" goto view_log
if "%choice%"=="15" goto test_launch
if "%choice%"=="0"  goto :eof

echo  Invalid option.
timeout /t 1 /nobreak >nul
goto menu

:: ============================================================
::  PREREQUISITES CHECK
:: ============================================================
:check_prereqs
echo.
echo  [*] Checking prerequisites...
echo  ========================================================

:: Test signing
for /f "tokens=*" %%a in ('bcdedit /enum ^| findstr /i "testsigning"') do set "TS=%%a"
echo %TS% | findstr /i "Yes" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] Test signing is OFF -- unsigned drivers will not load
    echo         Fix: bcdedit /set testsigning on   then reboot
) else (
    echo  [OK] Test signing enabled
)

:: Binary files
echo.
echo  Binaries:
if exist "%AGENT_EXE%" (echo    [OK] VettaiyanAgent.exe) else (echo    [MISS] VettaiyanAgent.exe)
if exist "%DRIVER_SYS%" (echo    [OK] VettaiyanDriver.sys) else (echo    [--] VettaiyanDriver.sys not found)
if exist "%FILTER_SYS%" (echo    [OK] VettaiyanFilter.sys) else (echo    [--] VettaiyanFilter.sys not found)

:: vcpkg DLLs
echo.
echo  Runtime DLLs:
set "DLL_OK=1"
for %%d in (magic-1.dll sqlite3.dll libcrypto-3-x64.dll libssl-3-x64.dll tre.dll getopt.dll legacy.dll brotlicommon.dll brotlidec.dll brotlienc.dll) do (
    if exist "%EDR_DIR%\%%d" (echo    [OK] %%d) else (echo    [MISS] %%d & set "DLL_OK=0")
)

:: CRT DLLs
echo.
echo  MSVC CRT:
for %%d in (vcruntime140d.dll msvcp140d.dll ucrtbased.dll vcruntime140.dll msvcp140.dll) do (
    if exist "%EDR_DIR%\%%d" (echo    [OK] %%d) else (echo    [--] %%d not found - OK if static CRT /MT)
)

:: Data files
echo.
echo  Data Files:
if exist "%EDR_DIR%\magic.mgc" (echo    [OK] magic.mgc) else (echo    [MISS] magic.mgc)
if exist "%EDR_DIR%\rules\vettaiyan.rules" (echo    [OK] rules\vettaiyan.rules) else (echo    [MISS] rules\vettaiyan.rules)

:: Web dashboard
echo.
echo  Web Dashboard:
if exist "%WEB_DIR%\index.html" (echo    [OK] web\index.html) else (echo    [MISS] web\index.html)
if exist "%WEB_DIR%\style.css"  (echo    [OK] web\style.css)  else (echo    [MISS] web\style.css)
if exist "%WEB_DIR%\app.js"     (echo    [OK] web\app.js)     else (echo    [MISS] web\app.js)

:: Dashboard reachability
echo.
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri '%DASHBOARD_URL%' -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop; Write-Host '  [OK] Dashboard reachable at %DASHBOARD_URL%' } catch { Write-Host '  [--] Dashboard not reachable (agent may not be running)' }"

echo.
echo  ========================================================
echo  Tip: Use option 15 to test-launch if the agent won't start.
pause
goto menu

:: ============================================================
::  STATUS
:: ============================================================
:status_all
echo.
echo  ========================================================
echo   VettaiyanEDR Status
echo  ========================================================
echo.

:: Kernel Driver
echo  [Kernel Driver]
sc.exe query %DRIVER_SVC% >nul 2>&1
if %errorlevel% neq 0 (
    echo    NOT INSTALLED
) else (
    for /f "tokens=3,4" %%a in ('sc.exe query %DRIVER_SVC% ^| findstr "STATE"') do echo    %%a %%b
)
echo.

:: Filesystem Filter
echo  [Filesystem Filter]
sc.exe query %FILTER_SVC% >nul 2>&1
if %errorlevel% neq 0 (
    echo    NOT INSTALLED
) else (
    for /f "tokens=3,4" %%a in ('sc.exe query %FILTER_SVC% ^| findstr "STATE"') do echo    %%a %%b
)
fltmc 2>nul | findstr /i "VettaiyanFilter" >nul 2>&1
if %errorlevel% equ 0 (echo    fltmc: LOADED) else (echo    fltmc: NOT LOADED)
echo.

:: Agent Service
echo  [Agent Service]
sc.exe query %AGENT_SVC% >nul 2>&1
if %errorlevel% neq 0 (
    echo    NOT INSTALLED
) else (
    for /f "tokens=3,4" %%a in ('sc.exe query %AGENT_SVC% ^| findstr "STATE"') do echo    %%a %%b
)
echo    Pipes:
if exist "\\.\pipe\VettaiyanScanner" (echo      Scanner: ACTIVE) else (echo      Scanner: INACTIVE)
if exist "\\.\pipe\VettaiyanCommand" (echo      Command: ACTIVE) else (echo      Command: INACTIVE)
echo.

:: Web Dashboard
echo  [Web Dashboard]
powershell -NoProfile -Command "try { $null = Invoke-WebRequest -Uri '%DASHBOARD_URL%' -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop; Write-Host '    ONLINE  %DASHBOARD_URL%' } catch { Write-Host '    OFFLINE' }"
echo.

:: Log
if exist "%EDR_DIR%\VettaiyanLogFile.log" (echo  [Log] Present) else (echo  [Log] Not found)
echo.

:: Test Signing
echo  [System]
for /f "tokens=*" %%a in ('bcdedit /enum ^| findstr /i "testsigning"') do echo    %%a
echo.

echo  ========================================================
pause
goto menu

:: ============================================================
::  INSTALL ALL
:: ============================================================
:install_all
echo.
echo  ========================================================
echo   Installing ALL VettaiyanEDR components
echo  ========================================================

:: --- Driver ---
echo.
echo  [1/3] Kernel Driver
if not exist "%DRIVER_SYS%" (
    echo    SKIP - VettaiyanDriver.sys not found
    goto install_all_filter
)
if exist "%DRIVER_CER%" (
    certutil -f -addstore TrustedPublisher "%DRIVER_CER%" >nul 2>&1
    certutil -f -addstore Root "%DRIVER_CER%" >nul 2>&1
)
copy /y "%DRIVER_SYS%" "%SystemRoot%\System32\drivers\VettaiyanDriver.sys" >nul
sc.exe query %DRIVER_SVC% >nul 2>&1 && (sc.exe stop %DRIVER_SVC% >nul 2>&1 & timeout /t 1 /nobreak >nul & sc.exe delete %DRIVER_SVC% >nul 2>&1 & timeout /t 1 /nobreak >nul)
sc.exe create %DRIVER_SVC% type= kernel binPath= "%SystemRoot%\System32\drivers\VettaiyanDriver.sys" start= demand >nul 2>&1
sc.exe start %DRIVER_SVC% >nul 2>&1
if %errorlevel% equ 0 (echo    [OK] Started) else (echo    [FAIL] Failed to start)

:: --- Filter ---
:install_all_filter
echo.
echo  [2/3] Filesystem Filter
if not exist "%FILTER_SYS%" (
    echo    SKIP - VettaiyanFilter.sys not found
    goto install_all_agent
)
if exist "%FILTER_CER%" (
    certutil -f -addstore TrustedPublisher "%FILTER_CER%" >nul 2>&1
    certutil -f -addstore Root "%FILTER_CER%" >nul 2>&1
)
fltmc unload %FILTER_SVC% >nul 2>&1
sc.exe query %FILTER_SVC% >nul 2>&1 && (sc.exe stop %FILTER_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul & sc.exe delete %FILTER_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul)
del /f "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" >nul 2>&1
timeout /t 1 /nobreak >nul
copy /y "%FILTER_SYS%" "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" >nul 2>&1
if !errorlevel! neq 0 (
    if not exist "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" (
        echo    [FAIL] Failed to copy - file may be locked, try rebooting
        goto install_all_agent
    )
)
sc.exe create %FILTER_SVC% type= filesys binPath= "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" start= demand group= "FSFilter Activity Monitor" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter\Instances" /v "DefaultInstance" /t REG_SZ /d "Vettaiyan Filter Instance" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter\Instances\Vettaiyan Filter Instance" /v "Altitude" /t REG_SZ /d "369100" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter\Instances\Vettaiyan Filter Instance" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1
fltmc load %FILTER_SVC% >nul 2>&1
if !errorlevel! neq 0 (sc.exe start %FILTER_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul)
fltmc 2>nul | findstr /i "VettaiyanFilter" >nul 2>&1
if %errorlevel% equ 0 (echo    [OK] Loaded) else (echo    [FAIL] Failed to load)

:: --- Agent ---
:install_all_agent
echo.
echo  [3/3] Agent Service + Web Dashboard
if not exist "%AGENT_EXE%" (
    echo    SKIP - VettaiyanAgent.exe not found
    goto install_all_done
)
sc.exe query %AGENT_SVC% >nul 2>&1 && (sc.exe stop %AGENT_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul & sc.exe delete %AGENT_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul)
sc.exe create %AGENT_SVC% binPath= "%AGENT_EXE%" start= demand >nul 2>&1
sc.exe start %AGENT_SVC% >nul 2>&1
if %errorlevel% equ 0 (
    echo    [OK] Agent started
    echo.
    echo    Waiting for web server...
    timeout /t 3 /nobreak >nul
    echo.
    echo    Opening dashboard: %DASHBOARD_URL%
    start "" "%DASHBOARD_URL%"
) else (
    echo    [FAIL] Agent failed to start - check option 13/14/15
)

:install_all_done
echo.
echo  ========================================================
echo   Installation complete.
echo  ========================================================
pause
goto menu

:: ============================================================
::  UNINSTALL ALL
:: ============================================================
:uninstall_all
echo.
echo  ========================================================
echo   Uninstalling ALL VettaiyanEDR components
echo  ========================================================
echo.

echo  [1/3] Agent Service
sc.exe stop %AGENT_SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete %AGENT_SVC% >nul 2>&1
echo    [OK] Removed

echo.
echo  [2/3] Filesystem Filter
fltmc unload %FILTER_SVC% >nul 2>&1
sc.exe stop %FILTER_SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete %FILTER_SVC% >nul 2>&1
del /f "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter" /f >nul 2>&1
echo    [OK] Removed

echo.
echo  [3/3] Kernel Driver
sc.exe stop %DRIVER_SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete %DRIVER_SVC% >nul 2>&1
del /f "%SystemRoot%\System32\drivers\VettaiyanDriver.sys" >nul 2>&1
echo    [OK] Removed

echo.
echo  ========================================================
echo   All components uninstalled.
echo  ========================================================
pause
goto menu

:: ============================================================
::  START ALL
:: ============================================================
:start_all
echo.
echo  [*] Starting all components...
echo.

sc.exe start %DRIVER_SVC% >nul 2>&1
if %errorlevel% equ 0 (echo  [OK] Driver started) else (echo  [--] Driver - not installed or already running)

fltmc load %FILTER_SVC% >nul 2>&1
if %errorlevel% equ 0 (echo  [OK] Filter loaded) else (echo  [--] Filter - not installed or already loaded)

sc.exe start %AGENT_SVC% >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] Agent started
    echo.
    echo  Waiting for web server...
    timeout /t 3 /nobreak >nul
    echo.
    set /p "OPEN_DASH=  Open dashboard in browser? (Y/n): "
    if /i not "!OPEN_DASH!"=="n" start "" "%DASHBOARD_URL%"
) else (
    echo  [--] Agent - not installed or already running
)

echo.
pause
goto menu

:: ============================================================
::  STOP ALL
:: ============================================================
:stop_all
echo.
echo  [*] Stopping all components...
echo.

sc.exe stop %AGENT_SVC% >nul 2>&1
if %errorlevel% equ 0 (echo  [OK] Agent stopped) else (echo  [--] Agent was not running)

fltmc unload %FILTER_SVC% >nul 2>&1
if %errorlevel% equ 0 (echo  [OK] Filter unloaded) else (echo  [--] Filter was not loaded)

sc.exe stop %DRIVER_SVC% >nul 2>&1
if %errorlevel% equ 0 (echo  [OK] Driver stopped) else (echo  [--] Driver was not running)

echo.
pause
goto menu

:: ============================================================
::  OPEN DASHBOARD
:: ============================================================
:open_dashboard
echo.
:: Check if agent is running first
sc.exe query %AGENT_SVC% 2>nul | findstr /i "RUNNING" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Agent service is not running.
    set /p "START_AGENT=     Start agent first? (Y/n): "
    if /i not "!START_AGENT!"=="n" (
        sc.exe start %AGENT_SVC% >nul 2>&1
        if !errorlevel! equ 0 (
            echo  [OK] Agent started
            timeout /t 3 /nobreak >nul
        ) else (
            echo  [FAIL] Failed to start agent - install it first (option 1 or 11)
            pause
            goto menu
        )
    )
)
echo  [*] Opening %DASHBOARD_URL%
start "" "%DASHBOARD_URL%"
echo  [OK] Browser launched
echo.
pause
goto menu

:: ============================================================
::  INSTALL KERNEL DRIVER
:: ============================================================
:install_driver
echo.
echo  [*] Installing VettaiyanDriver...
echo  --------------------------------------------------------

if not exist "%DRIVER_SYS%" (
    echo  [ERROR] VettaiyanDriver.sys not found at: %DRIVER_SYS%
    pause
    goto menu
)

if exist "%DRIVER_CER%" (
    echo  [*] Installing certificate...
    certutil -f -addstore TrustedPublisher "%DRIVER_CER%" >nul 2>&1
    certutil -f -addstore Root "%DRIVER_CER%" >nul 2>&1
    echo  [OK] Certificate installed
)

echo  [*] Copying to System32\drivers...
copy /y "%DRIVER_SYS%" "%SystemRoot%\System32\drivers\VettaiyanDriver.sys" >nul
if %errorlevel% neq 0 (
    echo  [ERROR] Failed to copy
    pause
    goto menu
)

sc.exe query %DRIVER_SVC% >nul 2>&1
if %errorlevel% equ 0 (
    sc.exe stop %DRIVER_SVC% >nul 2>&1
    sc.exe delete %DRIVER_SVC% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

sc.exe create %DRIVER_SVC% type= kernel binPath= "%SystemRoot%\System32\drivers\VettaiyanDriver.sys" start= demand
if %errorlevel% neq 0 (
    echo  [ERROR] Failed to create service
    pause
    goto menu
)

sc.exe start %DRIVER_SVC%
if %errorlevel% neq 0 (
    echo  [ERROR] Failed to start - check test signing
) else (
    echo  [OK] VettaiyanDriver is RUNNING
)
echo.
pause
goto menu

:: ============================================================
::  INSTALL FILESYSTEM FILTER
:: ============================================================
:install_filter
echo.
echo  [*] Installing VettaiyanFilter...
echo  --------------------------------------------------------

if not exist "%FILTER_SYS%" (
    echo  [ERROR] VettaiyanFilter.sys not found at: %FILTER_SYS%
    pause
    goto menu
)

if exist "%FILTER_CER%" (
    echo  [*] Installing certificate...
    certutil -f -addstore TrustedPublisher "%FILTER_CER%" >nul 2>&1
    certutil -f -addstore Root "%FILTER_CER%" >nul 2>&1
    echo  [OK] Certificate installed
)

echo  [*] Stopping existing filter...
fltmc unload %FILTER_SVC% >nul 2>&1
sc.exe query %FILTER_SVC% >nul 2>&1 && (sc.exe stop %FILTER_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul & sc.exe delete %FILTER_SVC% >nul 2>&1 & timeout /t 2 /nobreak >nul)

echo  [*] Copying to System32\drivers...
del /f "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" >nul 2>&1
timeout /t 1 /nobreak >nul
copy /y "%FILTER_SYS%" "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" >nul 2>&1
if %errorlevel% neq 0 (
    if not exist "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" (
        echo  [ERROR] Failed to copy filter - file may be locked
        pause
        goto menu
    )
    echo  [*] Copy returned error but existing .sys found - proceeding
)

sc.exe create %FILTER_SVC% type= filesys binPath= "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" start= demand group= "FSFilter Activity Monitor" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter\Instances" /v "DefaultInstance" /t REG_SZ /d "Vettaiyan Filter Instance" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter\Instances\Vettaiyan Filter Instance" /v "Altitude" /t REG_SZ /d "369100" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter\Instances\Vettaiyan Filter Instance" /v "Flags" /t REG_DWORD /d "0" /f >nul 2>&1

echo  [*] Loading filter...
fltmc load %FILTER_SVC% >nul 2>&1
if %errorlevel% neq 0 (sc.exe start %FILTER_SVC% >nul 2>&1)

fltmc | findstr /i "VettaiyanFilter" >nul 2>&1
if %errorlevel% equ 0 (echo  [OK] VettaiyanFilter is LOADED) else (echo  [*] VettaiyanFilter not visible - may need reboot)
echo.
pause
goto menu

:: ============================================================
::  INSTALL AGENT SERVICE
:: ============================================================
:install_agent
echo.
echo  [*] Installing Vettaiyan Agent Service...
echo  --------------------------------------------------------

if not exist "%AGENT_EXE%" (
    echo  [ERROR] VettaiyanAgent.exe not found
    pause
    goto menu
)

:: Check runtime + web files
set "MISSING=0"
for %%d in (magic-1.dll sqlite3.dll libcrypto-3-x64.dll libssl-3-x64.dll tre.dll getopt.dll legacy.dll brotlicommon.dll brotlidec.dll brotlienc.dll) do (
    if not exist "%EDR_DIR%\%%d" (echo  [MISS] %%d & set "MISSING=1")
)
if not exist "%WEB_DIR%\index.html" (echo  [MISS] web\index.html - dashboard won't work & set "MISSING=1")
if "%MISSING%"=="1" (
    echo.
    set /p cont="  Continue anyway? (y/N): "
    if /i not "!cont!"=="y" goto menu
)

sc.exe query %AGENT_SVC% >nul 2>&1
if %errorlevel% equ 0 (
    echo  [*] Removing stale service...
    sc.exe stop %AGENT_SVC% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc.exe delete %AGENT_SVC% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

echo  [*] Creating service...
sc.exe create %AGENT_SVC% binPath= "%AGENT_EXE%" start= demand
if %errorlevel% neq 0 (
    echo  [ERROR] Failed to create service
    pause
    goto menu
)

echo  [*] Starting agent...
sc.exe start %AGENT_SVC%
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Service failed to start.
    echo    - Check option 13 for prereqs, option 14 for log, option 15 for DLL diagnostic
) else (
    echo  [OK] Vettaiyan agent is RUNNING
    echo.
    echo  Waiting for web server...
    timeout /t 3 /nobreak >nul
    echo  Dashboard: %DASHBOARD_URL%
    set /p "OPEN_DASH=  Open dashboard? (Y/n): "
    if /i not "!OPEN_DASH!"=="n" start "" "%DASHBOARD_URL%"
)
echo.
pause
goto menu

:: ============================================================
::  UNINSTALL KERNEL DRIVER
:: ============================================================
:uninstall_driver
echo.
echo  [*] Uninstalling VettaiyanDriver...

sc.exe query %DRIVER_SVC% >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Not installed - nothing to do
    pause
    goto menu
)

sc.exe stop %DRIVER_SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete %DRIVER_SVC%
del /f "%SystemRoot%\System32\drivers\VettaiyanDriver.sys" >nul 2>&1
echo  [OK] VettaiyanDriver uninstalled
echo.
pause
goto menu

:: ============================================================
::  UNINSTALL FILESYSTEM FILTER
:: ============================================================
:uninstall_filter
echo.
echo  [*] Uninstalling VettaiyanFilter...

fltmc unload %FILTER_SVC% >nul 2>&1
sc.exe query %FILTER_SVC% >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Not installed - nothing to do
    pause
    goto menu
)

sc.exe stop %FILTER_SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete %FILTER_SVC%
del /f "%SystemRoot%\System32\drivers\VettaiyanFilter.sys" >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\VettaiyanFilter" /f >nul 2>&1
echo  [OK] VettaiyanFilter uninstalled
echo.
pause
goto menu

:: ============================================================
::  UNINSTALL AGENT SERVICE
:: ============================================================
:uninstall_agent
echo.
echo  [*] Uninstalling Vettaiyan Agent...

sc.exe query %AGENT_SVC% >nul 2>&1
if %errorlevel% neq 0 (
    echo  [*] Not installed - nothing to do
    pause
    goto menu
)

sc.exe stop %AGENT_SVC% >nul 2>&1
timeout /t 3 /nobreak >nul
sc.exe delete %AGENT_SVC%
echo  [OK] Vettaiyan agent uninstalled
echo.
pause
goto menu

:: ============================================================
::  VIEW AGENT LOG
:: ============================================================
:view_log
echo.
set "LOGFILE=%EDR_DIR%\VettaiyanLogFile.log"
set "DIAGLOG=%EDR_DIR%\VettaiyanDiag.log"
set "FOUND_LOG=0"

if not exist "%DIAGLOG%" goto skip_diag
set "FOUND_LOG=1"
echo  ========================================================
echo   VettaiyanDiag.log  (early startup diagnostics)
echo  ========================================================
echo.
powershell -NoProfile -Command "Get-Content '%DIAGLOG%' -Tail 30"
echo.
:skip_diag

if not exist "%LOGFILE%" goto skip_mainlog
set "FOUND_LOG=1"
echo  ========================================================
echo   VettaiyanLogFile.log  (main agent log)
echo  ========================================================
echo.
powershell -NoProfile -Command "Get-Content '%LOGFILE%' -Tail 50"
echo.
:skip_mainlog

if "%FOUND_LOG%"=="0" (
    echo  [*] No log files found - agent creates them on first run.
)

echo  ========================================================
pause
goto menu

:: ============================================================
::  TEST AGENT LAUNCH (DIAGNOSTIC)
:: ============================================================
:test_launch
echo.
echo  ========================================================
echo   Diagnostic: Launch VettaiyanAgent.exe directly
echo  ========================================================
echo.
echo  Runs the agent outside SCM to reveal missing DLL errors.
echo  Expected result: error 1063 ("not started as a service").
echo  If you see a "DLL not found" popup, that DLL is the issue.
echo.
pause
echo  [*] Launching %AGENT_EXE% ...
echo  --------------------------------------------------------
"%AGENT_EXE%"
set LAUNCH_ERR=%errorlevel%
echo  --------------------------------------------------------
echo  Exit code: %LAUNCH_ERR%
echo.
if "%LAUNCH_ERR%"=="1063" (
    echo  [OK] All DLLs loaded. Error 1063 is expected outside SCM.
) else (
    echo  [FAIL] Crashed with code %LAUNCH_ERR%
    echo         -1073741515 = STATUS_DLL_NOT_FOUND - missing DLL
    echo         Check for "DLL not found" dialog above.
    echo         Run option 13 to see which DLLs are missing.
)
echo.
pause
goto menu