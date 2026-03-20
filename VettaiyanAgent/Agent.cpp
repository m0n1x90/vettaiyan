#include "Agent.h"
#include "Log.h"
#include "Notification.h"
#include "YaraScanner.h"
#include "Support.h"
#include "Utils.h"
#include "DbUtil.h"
#include "EventReceiver.h"
#include "ProcessTracker.h"
#include "BehaviorEngine.h"
#include "EtwConsumer.h"
#include "ResponseEngine.h"
#include "TelemetryDb.h"
#include "TelemetryShipper.h"
#include "WebServer.h"

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

/* Forward declaration — defined later in this file */
static void DiagLog(const wchar_t* msg);

SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE                g_CurrentPipe = INVALID_HANDLE_VALUE;
HANDLE                g_WorkerThread = nullptr;
HANDLE                g_CommandThread = nullptr;

std::queue<std::wstring> g_scanQueue;
CRITICAL_SECTION g_queueLock;
HANDLE g_queueEvent = NULL;

void EnqueuePath(const std::wstring& path) {
    EnterCriticalSection(&g_queueLock);
    g_scanQueue.push(path);
    LeaveCriticalSection(&g_queueLock);
    SetEvent(g_queueEvent);
}

void EnqueueFilesInDirectory(const std::wstring& directory) {
    std::wstring searchPath = directory + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = directory + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EnqueueFilesInDirectory(fullPath);
        }
        else {
            EnqueuePath(fullPath);
        }

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

bool DequeuePath(std::wstring& pathOut) {
    EnterCriticalSection(&g_queueLock);
    if (g_scanQueue.empty()) {
        LeaveCriticalSection(&g_queueLock);
        return false;
    }
    pathOut = g_scanQueue.front();
    g_scanQueue.pop();
    LeaveCriticalSection(&g_queueLock);
    return true;
}

/* ============================================================
 *  SHA256 File Hashing (BCrypt / CNG)
 *  Computes hash for FileClose events on priority extensions.
 *  Filter sends NT device paths (\Device\HarddiskVolume2\...)
 *  so we prepend \\?\GLOBALROOT to open via Win32.
 * ============================================================ */
#define SHA256_MAX_FILE_SIZE (100LL * 1024 * 1024)  /* 100 MB limit */

static bool ShouldHashFile(const wchar_t* filePath)
{
    if (!filePath || wcslen(filePath) < 3) return false;
    const wchar_t* dot = wcsrchr(filePath, L'.');
    if (!dot || *(dot + 1) == L'\0') return false;
    const wchar_t* ext = dot + 1;
    for (size_t i = 0; i < EDR_SCAN_EXTENSION_COUNT; i++) {
        if (_wcsicmp(ext, EDR_SCAN_EXTENSIONS[i]) == 0) return true;
    }
    return false;
}

static bool ComputeFileSha256(const wchar_t* ntPath, char* hashOut65)
{
    hashOut65[0] = '\0';

    /* Convert NT device path to Win32: \Device\... → \\?\GLOBALROOT\Device\... */
    std::wstring win32Path;
    if (wcsncmp(ntPath, L"\\Device\\", 8) == 0) {
        win32Path = L"\\\\?\\GLOBALROOT";
        win32Path += ntPath;
    } else {
        win32Path = ntPath;
    }

    HANDLE hFile = CreateFileW(win32Path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > SHA256_MAX_FILE_SIZE || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return false;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
            BYTE buf[65536];
            DWORD bytesRead;
            while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
                BCryptHashData(hHash, buf, bytesRead, 0);
            }
            BYTE hash[32];
            if (BCryptFinishHash(hHash, hash, 32, 0) == 0) {
                for (int i = 0; i < 32; i++)
                    sprintf_s(hashOut65 + i * 2, 3, "%02x", hash[i]);
                hashOut65[64] = '\0';
                ok = true;
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    CloseHandle(hFile);
    return ok;
}

/* ============================================================
 *  Kernel Event Processing Callback
 *  This is the central event dispatcher - routes kernel events
 *  to process tracker, behavior engine, and telemetry DB.
 * ============================================================ */
static void OnKernelEventInner(const EDR_EVENT_HEADER* header, const void* eventData, ULONG eventSize);

void OnKernelEvent(const EDR_EVENT_HEADER* header, const void* eventData, ULONG eventSize)
{
    __try {
        OnKernelEventInner(header, eventData, eventSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        wchar_t buf[256];
        swprintf_s(buf, L"SEH in OnKernelEvent: 0x%08X eventType=%d",
            GetExceptionCode(), header ? header->EventType : -1);
        DiagLog(buf);
    }
}

static void OnKernelEventInner(const EDR_EVENT_HEADER* header, const void* eventData, ULONG eventSize)
{
    UNREFERENCED_PARAMETER(eventSize);
    if (!header) return;

    /* For FileClose on priority extensions, compute SHA256 before shipping.
       Uses BCrypt (CNG) to hash the file contents. Skips files > 100MB. */
    const char* sha256 = nullptr;
    char sha256Buf[65] = {};
    if (header->EventType == EdrEventFileClose) {
        const EDR_FILE_EVENT* fe = (const EDR_FILE_EVENT*)eventData;
        if (ShouldHashFile(fe->FilePath) && ComputeFileSha256(fe->FilePath, sha256Buf)) {
            sha256 = sha256Buf;
        }
    }

    /* Ship every event to the cloud backend (transit buffer → HTTP POST).
       This is the raw telemetry stream -- all event types, no filtering.
       The backend handles storage, indexing, and retention. */
    ShipEvent(header, eventData, sha256);

    switch (header->EventType) {
    case EdrEventProcessCreate:
    case EdrEventProcessTerminate:
        {
            const EDR_PROCESS_EVENT* procEvent = (const EDR_PROCESS_EVENT*)eventData;
            
            /* Update process tree */
            if (header->EventType == EdrEventProcessCreate) {
                OnProcessCreate(procEvent);
            } else {
                OnProcessTerminate(procEvent);
            }

            /* Behavioral analysis */
            AnalyzeProcessEvent(procEvent);

            /* Telemetry storage (only process create to reduce volume) */
            if (header->EventType == EdrEventProcessCreate) {
                std::wstring detail = L"PID=" + std::to_wstring(procEvent->Header.ProcessId) +
                    L" PPID=" + std::to_wstring(procEvent->ParentProcessId) +
                    L" Image=" + procEvent->ImagePath;
                StoreKernelEvent(header, detail);
            }
        }
        break;

    case EdrEventImageLoad:
        {
            const EDR_IMAGE_EVENT* imgEvent = (const EDR_IMAGE_EVENT*)eventData;
            OnImageLoad(imgEvent);
            AnalyzeImageEvent(imgEvent);
        }
        break;

    case EdrEventThreadCreate:
    case EdrEventThreadTerminate:
        {
            const EDR_THREAD_EVENT* threadEvent = (const EDR_THREAD_EVENT*)eventData;
            OnThreadEvent(threadEvent);
            AnalyzeThreadEvent(threadEvent);

            /* Store remote thread events as they're high-value */
            if (threadEvent->IsRemoteThread && header->EventType == EdrEventThreadCreate) {
                std::wstring detail = L"Remote thread: Source PID=" + std::to_wstring(header->ProcessId) +
                    L" Target PID=" + std::to_wstring(threadEvent->TargetProcessId);
                StoreKernelEvent(header, detail);
            }
        }
        break;

    case EdrEventRegistrySetValue:
    case EdrEventRegistryDeleteValue:
    case EdrEventRegistryDeleteKey:
    case EdrEventRegistryRenameKey:
    case EdrEventRegistryCreateKey:
        {
            const EDR_REGISTRY_EVENT* regEvent = (const EDR_REGISTRY_EVENT*)eventData;
            AnalyzeRegistryEvent(regEvent);

            /* Store mutation operations */
            if (header->EventType == EdrEventRegistrySetValue || 
                header->EventType == EdrEventRegistryDeleteKey) {
                std::wstring detail = L"PID=" + std::to_wstring(header->ProcessId) +
                    L" Key=" + regEvent->KeyPath;
                StoreKernelEvent(header, detail);
            }
        }
        break;

    case EdrEventFileCreate:
    case EdrEventFileWrite:
    case EdrEventFileDelete:
    case EdrEventFileRename:
    case EdrEventFileClose:
        {
            const EDR_FILE_EVENT* fileEvent = (const EDR_FILE_EVENT*)eventData;
            AnalyzeFileEvent(fileEvent);

            /* Auto-scan new executables on file close */
            if (header->EventType == EdrEventFileClose) {
                std::wstring filePath = fileEvent->FilePath;
                /* Queue for YARA scan if it has a priority extension */
            if (filePath.length() > 2) {
                std::wstring::size_type dot = filePath.rfind(L'.');
                if (dot != std::wstring::npos) {
                    std::wstring ext = filePath.substr(dot + 1);
                    for (size_t i = 0; i < EDR_SCAN_EXTENSION_COUNT; i++) {
                        if (_wcsicmp(ext.c_str(), EDR_SCAN_EXTENSIONS[i]) == 0) {
                            EnqueuePath(filePath);
                            break;
                        }
                    }
                }
            }
            }
        }
        break;

    case EdrEventHandleCreate:
    case EdrEventHandleDuplicate:
        {
            const EDR_HANDLE_EVENT* handleEvent = (const EDR_HANDLE_EVENT*)eventData;
            AnalyzeHandleEvent(handleEvent);
        }
        break;

    default:
        break;
    }
}


/* ============================================================
 *  Behavioral Detection Callback
 *  Called when the behavior engine fires a detection
 * ============================================================ */
void OnBehaviorDetection(const BehaviorDetection& detection)
{
    /* Store in telemetry DB */
    StoreBehaviorDetection(detection);

    LogMessage(L"[!] BEHAVIORAL DETECTION: " + detection.RuleName + L" - " + detection.Description +
        L" [" + detection.MitreTechnique + L"]");

    /* Auto-response based on severity */
    if (detection.Severity >= DetectionSeverity::High) {
        /* Send toast notification for high+ severity */
        std::vector<std::wstring> toastArgs = {
            L"detected",
            L"Behavioral Alert: " + detection.RuleName,
            detection.Description + L"\nMITRE: " + detection.MitreTechnique,
        };
        LaunchNotification(toastArgs);
    }

    if (detection.Severity >= DetectionSeverity::Critical) {
        /* Guard: never auto-kill critical Windows processes.
           Killing csrss, lsass, services, smss, wininit, etc. = instant BSOD. */
        bool safe = true;
        const ProcessNode* proc = GetProcessNode(detection.ProcessId);
        if (!proc || !proc->IsAlive) {
            safe = false;   /* PID gone or recycled */
        } else {
            static const wchar_t* PROTECTED[] = {
                L"system", L"smss.exe", L"csrss.exe", L"wininit.exe",
                L"services.exe", L"lsass.exe", L"winlogon.exe",
                L"svchost.exe", L"dwm.exe", L"fontdrvhost.exe",
                L"msdtc.exe", L"spoolsv.exe",
            };
            for (auto& p : PROTECTED) {
                if (_wcsicmp(proc->ImageName.c_str(), p) == 0) { safe = false; break; }
            }
            if (detection.ProcessId <= 4) safe = false;  /* PID 0 (Idle) / PID 4 (System) */
            if (proc->SessionId == 0 && proc->ParentProcessId <= 4) safe = false; /* Session-0 system service */
        }

        if (safe) {
            LogMessage(L"[!] AUTO-RESPONSE: Killing PID " + std::to_wstring(detection.ProcessId) +
                L" due to critical detection: " + detection.RuleName);
            KillProcess(detection.ProcessId);
        } else {
            LogMessage(L"[!] CRITICAL DETECTION on protected/system process PID " +
                std::to_wstring(detection.ProcessId) + L" — auto-kill suppressed: " + detection.RuleName);
        }
    }
}


/* ============================================================
 *  ETW Event Callback
 * ============================================================ */
void OnEtwEvent(const EtwEvent& event)
{
    std::wstring typeStr;
    switch (event.Type) {
    case EtwEventType::NetworkConnect:    typeStr = L"NetworkConnect"; break;
    case EtwEventType::NetworkDisconnect: typeStr = L"NetworkDisconnect"; break;
    case EtwEventType::DnsQuery:          typeStr = L"DnsQuery"; break;
    case EtwEventType::PowerShellCommand: typeStr = L"PowerShell"; break;
    }

    StoreEtwEvent(typeStr, event.ProcessId, event.Detail);
}


/* ============================================================
 *  YARA Scanner Worker Thread
 * ============================================================ */
DWORD WINAPI ScannerWorkerThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        WaitForSingleObject(g_queueEvent, INFINITE);

        std::wstring path;
        while (DequeuePath(path)) {
            YaraScanResult scanResult = ScanFileWithYara(path);

            if (scanResult.matched) {
                SaveScanResultToDB(scanResult);

                /* Auto-quarantine detected files */
                QuarantineFile(path, scanResult.ruleName);

                std::vector<std::wstring> toastArgs = {
                    L"detected",
                    L"YARA Detection: " + scanResult.ruleName,
                    scanResult.reason,
                };
                LaunchNotification(toastArgs);

                LogMessage(L"[!] YARA MATCH: " + scanResult.ruleName + L" on " + path);
            }
        }
    }
    return 0;
}


/* ============================================================
 *  Command Pipe Handler
 *  Receives commands from the UI (kill, quarantine, isolate, etc.)
 * ============================================================ */
DWORD WINAPI CommandWorkerThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);

    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPCWSTR sddl = L"D:(A;OICI;GRGW;;;WD)";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        return ERROR_ACCESS_DENIED;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    wchar_t buffer[2048];

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        HANDLE pipe = CreateNamedPipe(
            COMMAND_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(buffer),
            sizeof(buffer),
            0,
            &sa
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            DWORD bytesRead;
            if (ReadFile(pipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
                buffer[bytesRead / sizeof(wchar_t)] = L'\0';
                std::wstring command(buffer);

                LogMessage(L"[ Agent ] Command received: " + command);

                /* Parse command: "action|param1|param2" */
                size_t pos1 = command.find(L'|');
                std::wstring action = (pos1 != std::wstring::npos) ? command.substr(0, pos1) : command;
                std::wstring param = (pos1 != std::wstring::npos) ? command.substr(pos1 + 1) : L"";

                std::wstring response = L"ERROR";

                if (action == L"KILL") {
                    ULONG pid = (ULONG)std::stoul(param);
                    auto result = KillProcess(pid);
                    response = result.Detail;
                }
                else if (action == L"QUARANTINE") {
                    auto result = QuarantineFile(param, L"ManualQuarantine");
                    response = result.Detail;
                }
                else if (action == L"ISOLATE") {
                    auto result = IsolateEndpoint();
                    response = result.Detail;
                }
                else if (action == L"UNISOLATE") {
                    auto result = RemoveEndpointIsolation();
                    response = result.Detail;
                }
                else if (action == L"STATUS") {
                    response = L"RUNNING|Driver=" + std::wstring(IsDriverConnected() ? L"Connected" : L"Disconnected") +
                        L"|Filter=" + std::wstring(IsFilterConnected() ? L"Connected" : L"Disconnected") +
                        L"|Isolated=" + std::wstring(IsEndpointIsolated() ? L"Yes" : L"No") +
                        L"|Processes=" + std::to_wstring(GetActiveProcessCount()) +
                        L"|Detections=" + std::to_wstring(GetDetectionCount());
                }

                /* Send response */
                DWORD written;
                WriteFile(pipe, response.c_str(), (DWORD)(response.size() * sizeof(wchar_t)), &written, NULL);
            }
        }

        CloseHandle(pipe);
    }

    LocalFree(pSD);
    return 0;
}


/* Early diagnostic log - writes directly via Win32, no CRT dependency */
static void DiagLog(const wchar_t* msg) {
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len == 0 || len == MAX_PATH) return;
    for (DWORD i = len; i > 0; i--) {
        if (path[i] == L'\\') {
            path[i + 1] = L'\0';
            break;
        }
    }
    wcscat_s(path, L"VettaiyanDiag.log");
    HANDLE hFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t line[1024];
        int n = swprintf_s(line, L"[%02d:%02d:%02d.%03d] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
        DWORD written;
        WriteFile(hFile, line, n * sizeof(wchar_t), &written, NULL);
        CloseHandle(hFile);
    }
}

/* ============================================================
 *  Main Service Worker
 * ============================================================ */
static DWORD ServiceWorkerThreadInner();  /* forward decl */

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    try {
        return ServiceWorkerThreadInner();
    }
    catch (const std::exception& ex) {
        wchar_t buf[512];
        swprintf_s(buf, L"FATAL C++ exception in ServiceWorkerThread: %S", ex.what());
        DiagLog(buf);
        LogMessage(buf);
        return ERROR_UNHANDLED_EXCEPTION;
    }
    catch (...) {
        DiagLog(L"FATAL unknown exception in ServiceWorkerThread");
        LogMessage(L"FATAL unknown exception in ServiceWorkerThread");
        return ERROR_UNHANDLED_EXCEPTION;
    }
}

static DWORD ServiceWorkerThreadInner() {

    DiagLog(L"ServiceWorkerThread started");

    LaunchNotification(START_MSG);
    LogMessage(L"[ VettaiyanAgent ] ====== SERVICE STARTING ======");
    DiagLog(L"Past LaunchNotification and first LogMessage");

    /* Phase 1: Initialize YARA scanner */
    DiagLog(L"Phase 1: Initializing YARA...");
    if (!InitializeYara()) {
        LogMessage(L"[ VettaiyanAgent ] Failed to initialize YARA");
        DiagLog(L"YARA init FAILED");
        return ERROR_INTERNAL_ERROR;
    }
    LogMessage(L"[ VettaiyanAgent ] YARA engine initialized");
    DiagLog(L"Phase 1 OK: YARA initialized");

    /* Phase 2: Initialize telemetry database (detections + alerts only) */
    DiagLog(L"Phase 2: Initializing TelemetryDb...");
    if (!InitializeTelemetryDb()) {
        LogMessage(L"[ VettaiyanAgent ] Failed to initialize telemetry DB (non-fatal)");
        DiagLog(L"Phase 2: TelemetryDb init failed (non-fatal)");
    } else {
        DiagLog(L"Phase 2 OK: TelemetryDb initialized");
    }

    /* Phase 2b: Initialize telemetry shipper (raw events → cloud backend).
       Config is loaded from vettaiyan.ini next to the executable. */
    DiagLog(L"Phase 2b: Initializing TelemetryShipper...");
    {
        std::wstring iniPath = GetAssetPath(L"vettaiyan.ini");

        /* Helper lambda: read a string from the [Shipper] section */
        auto readIni = [&](const wchar_t* key, const wchar_t* def) -> std::string {
            wchar_t buf[1024] = {};
            GetPrivateProfileStringW(L"Shipper", key, def, buf, _countof(buf), iniPath.c_str());
            int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 1) return {};
            std::string out(len - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, buf, -1, &out[0], len, nullptr, nullptr);
            return out;
        };
        auto readIniInt = [&](const wchar_t* key, int def) -> int {
            return (int)GetPrivateProfileIntW(L"Shipper", key, def, iniPath.c_str());
        };

        TelemetryShipperConfig shipConfig;
        shipConfig.Endpoint        = readIni(L"Endpoint", L"");
        shipConfig.IndexOrToken    = readIni(L"IndexOrToken", L"");
        shipConfig.AuthHeader      = readIni(L"AuthHeader", L"");
        shipConfig.BatchSize       = readIniInt(L"BatchSize", 500);
        shipConfig.FlushIntervalMs = readIniInt(L"FlushIntervalMs", 2000);
        shipConfig.MaxBufferSize   = readIniInt(L"MaxBufferSize", 50000);

        if (shipConfig.Endpoint.empty()) {
            LogMessage(L"[ VettaiyanAgent ] TelemetryShipper: No endpoint in vettaiyan.ini (shipping disabled)");
            DiagLog(L"Phase 2b: Shipper skipped (no endpoint)");
        } else if (!InitTelemetryShipper(shipConfig)) {
            LogMessage(L"[ VettaiyanAgent ] TelemetryShipper init failed (non-fatal)");
            DiagLog(L"Phase 2b: Shipper init failed (non-fatal)");
        } else {
            DiagLog(L"Phase 2b OK: TelemetryShipper initialized");
        }
    }

    /* Phase 3: Initialize process tracker */
    DiagLog(L"Phase 3: Initializing ProcessTracker...");
    InitializeProcessTracker();
    DiagLog(L"Phase 3 OK");

    /* Phase 4: Initialize behavioral detection engine */
    DiagLog(L"Phase 4: Initializing BehaviorEngine...");
    InitializeBehaviorEngine();
    RegisterDetectionCallback(OnBehaviorDetection);
    DiagLog(L"Phase 4 OK");

    /* Phase 5: Initialize response engine */
    DiagLog(L"Phase 5: Initializing ResponseEngine...");
    InitializeResponseEngine();
    DiagLog(L"Phase 5 OK");

    /* Phase 6: Initialize event receiver (kernel driver + filter) */
    DiagLog(L"Phase 6: Initializing EventReceiver...");
    RegisterEventCallback(OnKernelEvent);
    if (!InitializeEventReceiver()) {
        LogMessage(L"[ VettaiyanAgent ] Event receiver init failed (drivers may not be loaded)");
        DiagLog(L"Phase 6: EventReceiver init failed (non-fatal)");
    } else {
        DiagLog(L"Phase 6 OK");
    }

    /* Phase 7: Initialize ETW consumer */
    RegisterEtwCallback(OnEtwEvent);
    if (!InitializeEtwConsumer()) {
        LogMessage(L"[ VettaiyanAgent ] ETW consumer init failed (requires admin, non-fatal)");
    }

    /* Phase 8: Start scanner queue */
    InitializeCriticalSection(&g_queueLock);
    g_queueEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    CreateThread(NULL, 0, ScannerWorkerThread, NULL, 0, NULL);
    LogMessage(L"[ VettaiyanAgent ] YARA scanner thread started");

    /* Phase 9: Start command pipe handler */
    g_CommandThread = CreateThread(NULL, 0, CommandWorkerThread, NULL, 0, NULL);
    LogMessage(L"[ VettaiyanAgent ] Command handler started");

    /* Phase 10: Start embedded web server */
    DiagLog(L"Phase 10: Starting WebServer...");
    StartWebServer();
    LogMessage(L"[ VettaiyanAgent ] Web dashboard at http://127.0.0.1:9630");
    DiagLog(L"Phase 10 OK: WebServer started");

    /* Phase 11: Scanner pipe listener (existing IPC for scan requests) */
    LogMessage(L"[ VettaiyanAgent ] ====== ALL SYSTEMS OPERATIONAL ======");

    HANDLE pipe;
    wchar_t buffer[512];

    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;

    LPCWSTR sddl = L"D:(A;OICI;GRGW;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        LogMessage(L"[ VettaiyanAgent ] Failed to convert SDDL string to security descriptor");
        return ERROR_ACCESS_DENIED;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {

        pipe = CreateNamedPipe(
            SCANNER_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(buffer),
            sizeof(buffer),
            0,
            &sa
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            LogMessage(L"[ VettaiyanAgent ] Failed to create named pipe!");
            Sleep(1000);
            continue;
        }

        g_CurrentPipe = pipe;

        BOOL connected = ConnectNamedPipe(pipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            DWORD bytesRead;
            if (ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                std::wstring receivedPath(buffer, bytesRead / sizeof(wchar_t));
                LogMessage(L"[ VettaiyanAgent ] Scan request: " + receivedPath);

                if (PathIsDirectoryW(receivedPath.c_str())) {
                    EnqueueFilesInDirectory(receivedPath);
                }
                else {
                    EnqueuePath(receivedPath);
                }
            }
        }

        CloseHandle(pipe);
        g_CurrentPipe = INVALID_HANDLE_VALUE;
    }

    /* ====== SHUTDOWN SEQUENCE ====== */
    LogMessage(L"[ VettaiyanAgent ] ====== SHUTTING DOWN ======");

    StopWebServer();
    ShutdownTelemetryShipper();
    ShutdownEtwConsumer();
    ShutdownEventReceiver();
    ShutdownBehaviorEngine();
    ShutdownResponseEngine();
    ShutdownProcessTracker();
    ShutdownTelemetryDb();
    FinalizeYara();

    DeleteCriticalSection(&g_queueLock);
    CloseHandle(g_queueEvent);
    LocalFree(pSD);

    LaunchNotification(STOP_MSG);
    LogMessage(L"[ VettaiyanAgent ] ====== SERVICE STOPPED ======");
    return ERROR_SUCCESS;
}


void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        SetEvent(g_ServiceStopEvent);

        if (g_WorkerThread) {
            CancelSynchronousIo(g_WorkerThread);
        }
        if (g_CommandThread) {
            CancelSynchronousIo(g_CommandThread);
        }
        break;

    default:
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    DiagLog(L"ServiceMain() entered");

    g_StatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME.c_str(), ServiceCtrlHandler);
    if (!g_StatusHandle) {
        DiagLog(L"RegisterServiceCtrlHandlerW FAILED");
        return;
    }
    DiagLog(L"ServiceCtrlHandler registered");

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (g_ServiceStopEvent == nullptr) {
        DiagLog(L"CreateEvent FAILED");
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    DiagLog(L"Service status set to RUNNING");

    AddContextMenuEntry();

    g_WorkerThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (g_WorkerThread) {
        WaitForSingleObject(g_WorkerThread, INFINITE);
        CloseHandle(g_WorkerThread);
    }

    RemoveContextMenuEntry();
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* Global SEH crash handler -- catches access violations, stack overflows, etc.
   that try/catch(...) doesn't cover. Logs to VettaiyanDiag.log. */
static LONG WINAPI GlobalCrashHandler(EXCEPTION_POINTERS* ep) {
    wchar_t buf[256];
    swprintf_s(buf, L"FATAL SEH: code=0x%08X addr=0x%p",
        ep->ExceptionRecord->ExceptionCode,
        ep->ExceptionRecord->ExceptionAddress);
    DiagLog(buf);
    return EXCEPTION_CONTINUE_SEARCH;
}

int wmain() {
    SetUnhandledExceptionFilter(GlobalCrashHandler);
    DiagLog(L"wmain() entered");

    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME.c_str()), ServiceMain },
        { nullptr, nullptr }
    };

    DiagLog(L"Calling StartServiceCtrlDispatcherW...");
    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        DWORD err = GetLastError();
        wchar_t buf[128];
        swprintf_s(buf, L"StartServiceCtrlDispatcherW FAILED: %lu", err);
        DiagLog(buf);
        return err;
    }

    DiagLog(L"wmain() exiting normally");
    return 0;
}
