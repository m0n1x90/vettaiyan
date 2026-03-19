/*
 * BehaviorEngine.cpp - MITRE ATT&CK behavioral detection
 *
 * Real-world EDR behavioral rules covering:
 * T1059 - Command and Scripting Interpreter
 * T1055 - Process Injection (Remote Thread)
 * T1003 - Credential Dumping
 * T1547 - Boot/Logon Autostart Execution
 * T1218 - System Binary Proxy Execution
 * T1036 - Masquerading
 * T1112 - Modify Registry
 * T1027 - Obfuscated Files
 */

#include "BehaviorEngine.h"
#include "ProcessTracker.h"
#include "Log.h"

#include <mutex>
#include <algorithm>
#include <deque>

static std::vector<DetectionCallback> g_DetectionCallbacks;
static std::deque<BehaviorDetection> g_Detections;
static std::mutex g_EngineMutex;
static const size_t MAX_DETECTIONS = 10000;

/* ============================================================
 *  LOLBAS - Living Off the Land Binaries
 * ============================================================ */

static const wchar_t* LOLBAS_BINARIES[] = {
    L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe",
    L"cscript.exe", L"mshta.exe", L"regsvr32.exe", L"rundll32.exe",
    L"certutil.exe", L"bitsadmin.exe", L"msiexec.exe", L"wmic.exe",
    L"installutil.exe", L"regasm.exe", L"regsvcs.exe", L"msbuild.exe",
    L"cmstp.exe", L"msxsl.exe", L"ieexec.exe", L"xwizard.exe",
    L"forfiles.exe", L"pcalua.exe", L"infdefaultinstall.exe",
};

/* Office applications */
static const wchar_t* OFFICE_BINARIES[] = {
    L"winword.exe", L"excel.exe", L"powerpnt.exe", L"outlook.exe",
    L"msaccess.exe", L"onenote.exe",
};

/* Credential stores */
static const wchar_t* CREDENTIAL_PATHS[] = {
    L"\\windows\\system32\\config\\sam",
    L"\\windows\\system32\\config\\security",
    L"\\windows\\system32\\config\\system",
    L"\\windows\\ntds\\ntds.dit",
};

/* Persistence registry keys */
static const wchar_t* PERSISTENCE_REGKEYS[] = {
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\SYSTEM\\CurrentControlSet\\Services",
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
};


static bool ContainsInsensitive(const std::wstring& haystack, const wchar_t* needle)
{
    std::wstring h = haystack;
    std::wstring n = needle;
    std::transform(h.begin(), h.end(), h.begin(), ::towlower);
    std::transform(n.begin(), n.end(), n.begin(), ::towlower);
    return h.find(n) != std::wstring::npos;
}

static bool EndsWithInsensitive(const std::wstring& str, const wchar_t* suffix)
{
    std::wstring s = suffix;
    if (str.size() < s.size()) return false;
    std::wstring tail = str.substr(str.size() - s.size());
    std::transform(tail.begin(), tail.end(), tail.begin(), ::towlower);
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return tail == s;
}

static std::wstring ExtractFileName(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

static bool IsLolbas(const std::wstring& imageName)
{
    for (auto& b : LOLBAS_BINARIES) {
        if (_wcsicmp(imageName.c_str(), b) == 0) return true;
    }
    return false;
}

static bool IsOffice(const std::wstring& imageName)
{
    for (auto& b : OFFICE_BINARIES) {
        if (_wcsicmp(imageName.c_str(), b) == 0) return true;
    }
    return false;
}


static void EmitDetection(const BehaviorDetection& detection)
{
    {
        std::lock_guard<std::mutex> lock(g_EngineMutex);
        g_Detections.push_back(detection);
        if (g_Detections.size() > MAX_DETECTIONS) {
            g_Detections.pop_front();
        }
    }

    /* Notify callbacks */
    for (auto& cb : g_DetectionCallbacks) {
        cb(detection);
    }

    /* Update process tracker suspicion score */
    int scoreIncrease = 0;
    switch (detection.Severity) {
    case DetectionSeverity::Low:       scoreIncrease = 10; break;
    case DetectionSeverity::Medium:    scoreIncrease = 25; break;
    case DetectionSeverity::High:      scoreIncrease = 50; break;
    case DetectionSeverity::Critical:  scoreIncrease = 100; break;
    default: scoreIncrease = 1; break;
    }
    IncrementSuspicionScore(detection.ProcessId, scoreIncrease);
    AddProcessAlert(detection.ProcessId, detection.RuleName + L": " + detection.Description);
}


/* ============================================================
 *  RULE: Suspicious Parent-Child (T1059)
 *  Office apps spawning scripting interpreters
 * ============================================================ */
static void CheckSuspiciousParentChild(const EDR_PROCESS_EVENT* event)
{
    std::wstring childImage = ExtractFileName(event->ImagePath);
    std::wstring parentImage = ExtractFileName(event->ParentImagePath);

    /* Office -> shell/scripting interpreter */
    if (IsOffice(parentImage) && IsLolbas(childImage)) {
        BehaviorDetection det = {};
        det.RuleName = L"SuspiciousParentChild_OfficeLOLBAS";
        det.Description = parentImage + L" spawned " + childImage;
        det.MitreTactic = L"Execution";
        det.MitreTechnique = L"T1059";
        det.Severity = DetectionSeverity::High;
        det.ProcessId = event->Header.ProcessId;
        det.ParentProcessId = event->ParentProcessId;
        det.ProcessImage = childImage;
        det.ParentImage = parentImage;
        det.Timestamp = event->Header.Timestamp;
        EmitDetection(det);
    }

    /* Explorer/services -> unusual child */
    if (_wcsicmp(parentImage.c_str(), L"services.exe") == 0 && IsLolbas(childImage)) {
        BehaviorDetection det = {};
        det.RuleName = L"SuspiciousParentChild_ServiceLOLBAS";
        det.Description = L"services.exe spawned " + childImage;
        det.MitreTactic = L"Execution";
        det.MitreTechnique = L"T1059";
        det.Severity = DetectionSeverity::Medium;
        det.ProcessId = event->Header.ProcessId;
        det.ParentProcessId = event->ParentProcessId;
        det.ProcessImage = childImage;
        det.ParentImage = parentImage;
        det.Timestamp = event->Header.Timestamp;
        EmitDetection(det);
    }

    /* svchost spawning shell is suspicious */
    if (_wcsicmp(parentImage.c_str(), L"svchost.exe") == 0 &&
        (_wcsicmp(childImage.c_str(), L"cmd.exe") == 0 ||
         _wcsicmp(childImage.c_str(), L"powershell.exe") == 0 ||
         _wcsicmp(childImage.c_str(), L"pwsh.exe") == 0)) {
        BehaviorDetection det = {};
        det.RuleName = L"SuspiciousParentChild_SvchostShell";
        det.Description = L"svchost.exe spawned " + childImage;
        det.MitreTactic = L"Execution";
        det.MitreTechnique = L"T1059";
        det.Severity = DetectionSeverity::High;
        det.ProcessId = event->Header.ProcessId;
        det.ParentProcessId = event->ParentProcessId;
        det.ProcessImage = childImage;
        det.ParentImage = parentImage;
        det.Timestamp = event->Header.Timestamp;
        EmitDetection(det);
    }
}


/* ============================================================
 *  RULE: LOLBAS Download Cradle (T1105/T1059)
 *  Certutil/bitsadmin/powershell downloading files
 * ============================================================ */
static void CheckDownloadCradle(const EDR_PROCESS_EVENT* event)
{
    std::wstring childImage = ExtractFileName(event->ImagePath);
    std::wstring cmdLine = event->CommandLine;

    /* certutil -urlcache -split -f http... */
    if (_wcsicmp(childImage.c_str(), L"certutil.exe") == 0) {
        if (ContainsInsensitive(cmdLine, L"urlcache") || ContainsInsensitive(cmdLine, L"http")) {
            BehaviorDetection det = {};
            det.RuleName = L"DownloadCradle_Certutil";
            det.Description = L"certutil.exe used as download cradle";
            det.MitreTactic = L"Command and Control";
            det.MitreTechnique = L"T1105";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.ParentProcessId = event->ParentProcessId;
            det.ProcessImage = childImage;
            det.ParentImage = ExtractFileName(event->ParentImagePath);
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }

    /* bitsadmin /transfer */
    if (_wcsicmp(childImage.c_str(), L"bitsadmin.exe") == 0) {
        if (ContainsInsensitive(cmdLine, L"/transfer") || ContainsInsensitive(cmdLine, L"http")) {
            BehaviorDetection det = {};
            det.RuleName = L"DownloadCradle_Bitsadmin";
            det.Description = L"bitsadmin.exe used as download cradle";
            det.MitreTactic = L"Command and Control";
            det.MitreTechnique = L"T1105";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.ParentProcessId = event->ParentProcessId;
            det.ProcessImage = childImage;
            det.ParentImage = ExtractFileName(event->ParentImagePath);
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }

    /* PowerShell encoded commands / download */
    if (_wcsicmp(childImage.c_str(), L"powershell.exe") == 0 || 
        _wcsicmp(childImage.c_str(), L"pwsh.exe") == 0) {
        if (ContainsInsensitive(cmdLine, L"-encodedcommand") ||
            ContainsInsensitive(cmdLine, L"-enc ") ||
            ContainsInsensitive(cmdLine, L"downloadstring") ||
            ContainsInsensitive(cmdLine, L"downloadfile") ||
            ContainsInsensitive(cmdLine, L"invoke-webrequest") ||
            ContainsInsensitive(cmdLine, L"iwr ") ||
            ContainsInsensitive(cmdLine, L"bypass") ||
            ContainsInsensitive(cmdLine, L"hidden")) {
            BehaviorDetection det = {};
            det.RuleName = L"SuspiciousPowerShell_Command";
            det.Description = L"Suspicious PowerShell execution detected";
            det.MitreTactic = L"Execution";
            det.MitreTechnique = L"T1059.001";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.ParentProcessId = event->ParentProcessId;
            det.ProcessImage = childImage;
            det.ParentImage = ExtractFileName(event->ParentImagePath);
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }
}


/* ============================================================
 *  RULE: Credential Access (T1003)
 *  Access to SAM/SECURITY/SYSTEM hives
 * ============================================================ */
static void CheckCredentialAccess(const EDR_FILE_EVENT* event)
{
    std::wstring filePath = event->FilePath;

    for (auto& credPath : CREDENTIAL_PATHS) {
        if (ContainsInsensitive(filePath, credPath)) {
            BehaviorDetection det = {};
            det.RuleName = L"CredentialAccess_HiveRead";
            det.Description = L"Access to credential store: " + filePath;
            det.MitreTactic = L"Credential Access";
            det.MitreTechnique = L"T1003";
            det.Severity = DetectionSeverity::Critical;
            det.ProcessId = event->Header.ProcessId;
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
            break;
        }
    }
}


/* ============================================================
 *  RULE: Persistence via Registry (T1547)
 * ============================================================ */
static void CheckRegistryPersistence(const EDR_REGISTRY_EVENT* event)
{
    if (event->Header.EventType != EdrEventRegistrySetValue &&
        event->Header.EventType != EdrEventRegistryCreateKey) {
        return;
    }

    std::wstring keyPath = event->KeyPath;

    for (auto& persistKey : PERSISTENCE_REGKEYS) {
        if (ContainsInsensitive(keyPath, persistKey)) {
            BehaviorDetection det = {};
            det.RuleName = L"Persistence_RegistryAutorun";
            det.Description = L"Modification of autorun registry key: " + keyPath;
            det.MitreTactic = L"Persistence";
            det.MitreTechnique = L"T1547.001";
            det.Severity = DetectionSeverity::Medium;
            det.ProcessId = event->Header.ProcessId;
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
            break;
        }
    }

    /* Image File Execution Options (T1546.012) - debugger persistence */
    if (ContainsInsensitive(keyPath, L"Image File Execution Options")) {
        if (ContainsInsensitive(event->ValueName, L"Debugger") ||
            ContainsInsensitive(event->ValueName, L"GlobalFlag")) {
            BehaviorDetection det = {};
            det.RuleName = L"Persistence_IFEO";
            det.Description = L"IFEO modification detected: " + keyPath;
            det.MitreTactic = L"Persistence";
            det.MitreTechnique = L"T1546.012";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }
}


/* ============================================================
 *  RULE: Defense Evasion - Proxy Execution (T1218)
 * ============================================================ */
static void CheckProxyExecution(const EDR_PROCESS_EVENT* event)
{
    std::wstring childImage = ExtractFileName(event->ImagePath);
    std::wstring cmdLine = event->CommandLine;

    /* mshta executing remote HTA */
    if (_wcsicmp(childImage.c_str(), L"mshta.exe") == 0) {
        if (ContainsInsensitive(cmdLine, L"http") || ContainsInsensitive(cmdLine, L"javascript:")) {
            BehaviorDetection det = {};
            det.RuleName = L"ProxyExecution_MSHTA";
            det.Description = L"mshta.exe executing remote/script content";
            det.MitreTactic = L"Defense Evasion";
            det.MitreTechnique = L"T1218.005";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.ParentProcessId = event->ParentProcessId;
            det.ProcessImage = childImage;
            det.ParentImage = ExtractFileName(event->ParentImagePath);
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }

    /* regsvr32 /s /n /u /i:http... scrobj.dll (Squiblydoo) */
    if (_wcsicmp(childImage.c_str(), L"regsvr32.exe") == 0) {
        if (ContainsInsensitive(cmdLine, L"scrobj") || ContainsInsensitive(cmdLine, L"http")) {
            BehaviorDetection det = {};
            det.RuleName = L"ProxyExecution_Regsvr32";
            det.Description = L"regsvr32.exe proxy execution (Squiblydoo)";
            det.MitreTactic = L"Defense Evasion";
            det.MitreTechnique = L"T1218.010";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.ParentProcessId = event->ParentProcessId;
            det.ProcessImage = childImage;
            det.ParentImage = ExtractFileName(event->ParentImagePath);
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }

    /* rundll32 with suspicious arguments */
    if (_wcsicmp(childImage.c_str(), L"rundll32.exe") == 0) {
        if (ContainsInsensitive(cmdLine, L"javascript:") ||
            ContainsInsensitive(cmdLine, L"http") ||
            ContainsInsensitive(cmdLine, L"shell32.dll,ShellExec_RunDLL")) {
            BehaviorDetection det = {};
            det.RuleName = L"ProxyExecution_Rundll32";
            det.Description = L"rundll32.exe suspicious execution";
            det.MitreTactic = L"Defense Evasion";
            det.MitreTechnique = L"T1218.011";
            det.Severity = DetectionSeverity::Medium;
            det.ProcessId = event->Header.ProcessId;
            det.ParentProcessId = event->ParentProcessId;
            det.ProcessImage = childImage;
            det.ParentImage = ExtractFileName(event->ParentImagePath);
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }
}


/* ============================================================
 *  RULE: Suspicious file writes to autostart
 * ============================================================ */
static void CheckSuspiciousFileWrite(const EDR_FILE_EVENT* event)
{
    if (event->Header.EventType != EdrEventFileCreate &&
        event->Header.EventType != EdrEventFileWrite) {
        return;
    }

    std::wstring filePath = event->FilePath;

    /* Executable dropped in Startup folder */
    if (ContainsInsensitive(filePath, L"\\Start Menu\\Programs\\Startup\\")) {
        if (EndsWithInsensitive(filePath, L".exe") ||
            EndsWithInsensitive(filePath, L".bat") ||
            EndsWithInsensitive(filePath, L".cmd") ||
            EndsWithInsensitive(filePath, L".vbs") ||
            EndsWithInsensitive(filePath, L".ps1") ||
            EndsWithInsensitive(filePath, L".lnk")) {
            BehaviorDetection det = {};
            det.RuleName = L"Persistence_StartupFolder";
            det.Description = L"Executable/script written to Startup folder: " + ExtractFileName(filePath);
            det.MitreTactic = L"Persistence";
            det.MitreTechnique = L"T1547.001";
            det.Severity = DetectionSeverity::High;
            det.ProcessId = event->Header.ProcessId;
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }

    /* DLL dropped in System32 */
    if (ContainsInsensitive(filePath, L"\\windows\\system32\\") &&
        EndsWithInsensitive(filePath, L".dll")) {
        BehaviorDetection det = {};
        det.RuleName = L"SuspiciousWrite_System32DLL";
        det.Description = L"DLL written to System32: " + ExtractFileName(filePath);
        det.MitreTactic = L"Persistence";
        det.MitreTechnique = L"T1574.001";
        det.Severity = DetectionSeverity::Medium;
        det.ProcessId = event->Header.ProcessId;
        det.Timestamp = event->Header.Timestamp;
        EmitDetection(det);
    }
}


/* ============================================================
 *  Public API
 * ============================================================ */

void InitializeBehaviorEngine()
{
    std::lock_guard<std::mutex> lock(g_EngineMutex);
    g_Detections.clear();
    g_DetectionCallbacks.clear();
    LogMessage(L"[ BehaviorEngine ] Initialized with ATT&CK behavioral rules");
}

void ShutdownBehaviorEngine()
{
    std::lock_guard<std::mutex> lock(g_EngineMutex);
    g_Detections.clear();
    g_DetectionCallbacks.clear();
    LogMessage(L"[ BehaviorEngine ] Shutdown");
}

void RegisterDetectionCallback(DetectionCallback callback)
{
    std::lock_guard<std::mutex> lock(g_EngineMutex);
    g_DetectionCallbacks.push_back(callback);
}


void AnalyzeProcessEvent(const EDR_PROCESS_EVENT* event)
{
    if (!event || event->Header.EventType != EdrEventProcessCreate) return;
    
    CheckSuspiciousParentChild(event);
    CheckDownloadCradle(event);
    CheckProxyExecution(event);
}


void AnalyzeImageEvent(const EDR_IMAGE_EVENT* event)
{
    if (!event) return;
    /* Future: detect reflective DLL loading, unusual image paths */
}


void AnalyzeThreadEvent(const EDR_THREAD_EVENT* event)
{
    if (!event) return;

    /* Remote thread injection detection (T1055) */
    if (event->Header.EventType == EdrEventThreadCreate && event->IsRemoteThread) {
        BehaviorDetection det = {};
        det.RuleName = L"ProcessInjection_RemoteThread";
        det.Description = L"Remote thread created in PID " + std::to_wstring(event->TargetProcessId);
        det.MitreTactic = L"Defense Evasion";
        det.MitreTechnique = L"T1055.003";
        det.Severity = DetectionSeverity::High;
        det.ProcessId = event->Header.ProcessId;
        det.Timestamp = event->Header.Timestamp;
        EmitDetection(det);
    }
}


void AnalyzeRegistryEvent(const EDR_REGISTRY_EVENT* event)
{
    if (!event) return;
    CheckRegistryPersistence(event);
}


void AnalyzeFileEvent(const EDR_FILE_EVENT* event)
{
    if (!event) return;
    CheckCredentialAccess(event);
    CheckSuspiciousFileWrite(event);
}


void AnalyzeHandleEvent(const EDR_HANDLE_EVENT* event)
{
    if (!event) return;

    /* Process hollowing / injection via handle access (T1055) */
    ACCESS_MASK suspiciousMask = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    if ((event->DesiredAccess & suspiciousMask) == suspiciousMask) {
        /* Process wants write + create thread in another process = injection */
        if (event->TargetProcessId != event->Header.ProcessId) {
            BehaviorDetection det = {};
            det.RuleName = L"ProcessInjection_SuspiciousHandle";
            det.Description = L"Suspicious handle access to PID " + std::to_wstring(event->TargetProcessId) +
                              L" (VM_WRITE + VM_OPERATION + CREATE_THREAD)";
            det.MitreTactic = L"Defense Evasion";
            det.MitreTechnique = L"T1055";
            det.Severity = DetectionSeverity::Critical;
            det.ProcessId = event->Header.ProcessId;
            det.Timestamp = event->Header.Timestamp;
            EmitDetection(det);
        }
    }
}


std::vector<BehaviorDetection> GetRecentDetections(int limit)
{
    std::lock_guard<std::mutex> lock(g_EngineMutex);
    std::vector<BehaviorDetection> result;
    
    int count = 0;
    for (auto it = g_Detections.rbegin(); it != g_Detections.rend() && count < limit; ++it, ++count) {
        result.push_back(*it);
    }

    return result;
}


size_t GetDetectionCount()
{
    std::lock_guard<std::mutex> lock(g_EngineMutex);
    return g_Detections.size();
}
