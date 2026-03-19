/*
 * ResponseEngine.cpp - Threat response implementation
 */

#include "ResponseEngine.h"
#include "EventReceiver.h"
#include "Log.h"
#include "Utils.h"

#include <fstream>
#include <chrono>
#include <ctime>
#include <mutex>
#include <deque>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

static std::wstring g_QuarantinePath;
static std::wstring g_QuarantineDbPath;
static bool g_IsIsolated = false;
static std::deque<ResponseResult> g_ResponseHistory;
static std::deque<QuarantineEntry> g_QuarantineEntries;
static std::mutex g_ResponseMutex;
static const size_t MAX_RESPONSE_HISTORY = 1000;


static std::wstring GetTimestampStr()
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm localTime;
    localtime_s(&localTime, &time);
    wchar_t buf[64];
    wcsftime(buf, sizeof(buf) / sizeof(buf[0]), L"%Y-%m-%d %H:%M:%S", &localTime);
    return buf;
}


static void RecordResponse(const ResponseResult& result)
{
    std::lock_guard<std::mutex> lock(g_ResponseMutex);
    g_ResponseHistory.push_back(result);
    if (g_ResponseHistory.size() > MAX_RESPONSE_HISTORY) {
        g_ResponseHistory.pop_front();
    }
}


void InitializeResponseEngine()
{
    /* Create quarantine directory */
    g_QuarantinePath = GetExecutableDir() + L"\\Quarantine";
    g_QuarantineDbPath = g_QuarantinePath + L"\\manifest.txt";

    CreateDirectoryW(g_QuarantinePath.c_str(), NULL);

    g_IsIsolated = false;
    LogMessage(L"[ ResponseEngine ] Initialized. Quarantine path: " + g_QuarantinePath);
}


void ShutdownResponseEngine()
{
    std::lock_guard<std::mutex> lock(g_ResponseMutex);
    g_ResponseHistory.clear();
    g_QuarantineEntries.clear();
    LogMessage(L"[ ResponseEngine ] Shutdown");
}


ResponseResult KillProcess(ULONG processId)
{
    ResponseResult result = {};
    result.Action = ResponseAction::KillProcess;
    result.Target = std::to_wstring(processId);

    /* Try kernel kill first (bypasses user-mode protections) */
    if (IsDriverConnected() && KillProcessViaDriver(processId, 1)) {
        result.Success = true;
        result.Detail = L"Process killed via kernel driver";
        LogMessage(L"[ ResponseEngine ] Killed PID " + result.Target + L" via driver");
    }
    else {
        /* Fallback to user-mode kill */
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
        if (hProcess) {
            if (TerminateProcess(hProcess, 1)) {
                result.Success = true;
                result.Detail = L"Process killed via user-mode";
                LogMessage(L"[ ResponseEngine ] Killed PID " + result.Target + L" via user-mode");
            }
            else {
                result.Success = false;
                result.ErrorCode = GetLastError();
                result.Detail = L"TerminateProcess failed: " + std::to_wstring(result.ErrorCode);
            }
            CloseHandle(hProcess);
        }
        else {
            result.Success = false;
            result.ErrorCode = GetLastError();
            result.Detail = L"OpenProcess failed: " + std::to_wstring(result.ErrorCode);
        }
    }

    RecordResponse(result);
    return result;
}


ResponseResult QuarantineFile(const std::wstring& filePath, const std::wstring& rule)
{
    ResponseResult result = {};
    result.Action = ResponseAction::QuarantineFile;
    result.Target = filePath;

    try {
        if (GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            result.Success = false;
            result.Detail = L"File not found";
            RecordResponse(result);
            return result;
        }

        /* Compute hash before moving */
        std::wstring fileHash = ComputeSHA256(filePath);

        /* Generate quarantine filename: hash_original.quarantine */
        std::wstring originalName = filePath.substr(filePath.find_last_of(L"\\/ ") + 1);
        std::wstring quarantineName = fileHash.substr(0, 16) + L"_" + originalName + L".quarantine";
        std::wstring quarantineDest = g_QuarantinePath + L"\\" + quarantineName;

        /* Move file to quarantine vault */
        if (!MoveFileExW(filePath.c_str(), quarantineDest.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
            result.Success = false;
            result.ErrorCode = GetLastError();
            result.Detail = L"MoveFile failed: " + std::to_wstring(result.ErrorCode);
            RecordResponse(result);
            return result;
        }

        /* Record quarantine entry */
        QuarantineEntry entry = {};
        entry.OriginalPath = filePath;
        entry.QuarantinePath = quarantineDest;
        entry.FileHash = fileHash;
        entry.DetectionRule = rule;
        entry.Timestamp = GetTimestampStr();

        {
            std::lock_guard<std::mutex> lock(g_ResponseMutex);
            g_QuarantineEntries.push_back(entry);
        }

        /* Write to manifest file */
        std::wofstream manifest(g_QuarantineDbPath, std::ios::app);
        if (manifest.is_open()) {
            manifest << entry.Timestamp << L"|"
                     << entry.OriginalPath << L"|"
                     << entry.QuarantinePath << L"|"
                     << entry.FileHash << L"|"
                     << entry.DetectionRule << std::endl;
        }

        result.Success = true;
        result.Detail = L"File quarantined to " + quarantineDest;
        LogMessage(L"[ ResponseEngine ] Quarantined: " + filePath + L" -> " + quarantineDest);

    } catch (const std::exception& ex) {
        result.Success = false;
        std::string msg = ex.what();
        result.Detail = std::wstring(msg.begin(), msg.end());
    }

    RecordResponse(result);
    return result;
}


ResponseResult RestoreQuarantinedFile(const std::wstring& quarantinePath)
{
    ResponseResult result = {};
    result.Action = ResponseAction::RestoreFromQuarantine;
    result.Target = quarantinePath;

    std::lock_guard<std::mutex> lock(g_ResponseMutex);

    /* Find the quarantine entry */
    for (auto it = g_QuarantineEntries.begin(); it != g_QuarantineEntries.end(); ++it) {
        if (it->QuarantinePath == quarantinePath) {
            if (MoveFileExW(quarantinePath.c_str(), it->OriginalPath.c_str(), MOVEFILE_COPY_ALLOWED)) {
                result.Success = true;
                result.Detail = L"Restored to " + it->OriginalPath;
                LogMessage(L"[ ResponseEngine ] Restored: " + quarantinePath + L" -> " + it->OriginalPath);
                g_QuarantineEntries.erase(it);
            } else {
                result.Success = false;
                result.ErrorCode = GetLastError();
                result.Detail = L"Restore failed: " + std::to_wstring(result.ErrorCode);
            }
            RecordResponse(result);
            return result;
        }
    }

    result.Success = false;
    result.Detail = L"Quarantine entry not found";
    RecordResponse(result);
    return result;
}


ResponseResult RemediateFile(const std::wstring& filePath)
{
    ResponseResult result = {};
    result.Action = ResponseAction::DeleteFile;
    result.Target = filePath;

    if (DeleteFileW(filePath.c_str())) {
        result.Success = true;
        result.Detail = L"File deleted permanently";
        LogMessage(L"[ ResponseEngine ] Deleted: " + filePath);
    } else {
        result.Success = false;
        result.ErrorCode = GetLastError();
        result.Detail = L"Delete failed: " + std::to_wstring(result.ErrorCode);
    }

    RecordResponse(result);
    return result;
}


ResponseResult IsolateEndpoint()
{
    ResponseResult result = {};
    result.Action = ResponseAction::IsolateNetwork;
    result.Target = L"Endpoint";

    /* 
     * Network isolation via Windows Firewall (netsh)
     * In production, use WFP (Windows Filtering Platform) APIs directly.
     * For now, add firewall rules to block all traffic except loopback.
     */
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    /* Block all inbound */
    std::wstring cmdIn = L"netsh advfirewall firewall add rule name=\"VettaiyanIsolation_In\" "
                         L"dir=in action=block enable=yes profile=any";

    /* Block all outbound */
    std::wstring cmdOut = L"netsh advfirewall firewall add rule name=\"VettaiyanIsolation_Out\" "
                          L"dir=out action=block enable=yes profile=any";

    /* Allow loopback for management */
    std::wstring cmdAllow = L"netsh advfirewall firewall add rule name=\"VettaiyanIsolation_Mgmt\" "
                            L"dir=out action=allow remoteip=127.0.0.1 enable=yes";

    /* Execute commands */
    BOOL ok = CreateProcessW(NULL, &cmdIn[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    ok = CreateProcessW(NULL, &cmdOut[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    ok = CreateProcessW(NULL, &cmdAllow[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    g_IsIsolated = true;
    result.Success = true;
    result.Detail = L"Endpoint network isolated - all traffic blocked except loopback";
    LogMessage(L"[ ResponseEngine ] ENDPOINT ISOLATED");

    RecordResponse(result);
    return result;
}


ResponseResult RemoveEndpointIsolation()
{
    ResponseResult result = {};
    result.Action = ResponseAction::RemoveIsolation;
    result.Target = L"Endpoint";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    std::wstring cmdRemoveIn = L"netsh advfirewall firewall delete rule name=\"VettaiyanIsolation_In\"";
    std::wstring cmdRemoveOut = L"netsh advfirewall firewall delete rule name=\"VettaiyanIsolation_Out\"";
    std::wstring cmdRemoveMgmt = L"netsh advfirewall firewall delete rule name=\"VettaiyanIsolation_Mgmt\"";

    CreateProcessW(NULL, &cmdRemoveIn[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    CreateProcessW(NULL, &cmdRemoveOut[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    CreateProcessW(NULL, &cmdRemoveMgmt[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }

    g_IsIsolated = false;
    result.Success = true;
    result.Detail = L"Endpoint isolation removed - network restored";
    LogMessage(L"[ ResponseEngine ] Endpoint isolation REMOVED");

    RecordResponse(result);
    return result;
}


std::vector<QuarantineEntry> GetQuarantinedFiles()
{
    std::lock_guard<std::mutex> lock(g_ResponseMutex);
    return std::vector<QuarantineEntry>(g_QuarantineEntries.begin(), g_QuarantineEntries.end());
}


bool IsEndpointIsolated()
{
    return g_IsIsolated;
}


std::vector<ResponseResult> GetResponseHistory(int limit)
{
    std::lock_guard<std::mutex> lock(g_ResponseMutex);
    std::vector<ResponseResult> result;
    int count = 0;
    for (auto it = g_ResponseHistory.rbegin(); it != g_ResponseHistory.rend() && count < limit; ++it, ++count) {
        result.push_back(*it);
    }
    return result;
}
