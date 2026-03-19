/*
 * ResponseEngine.h - Threat response actions
 *
 * Provides automated and manual response capabilities:
 * - Kill process (via kernel driver or user-mode)
 * - Quarantine file (move to secure vault with metadata)
 * - Network isolation (WFP-based firewall rules)
 * - File remediation (delete + registry cleanup)
 */

#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

#include <string>
#include <vector>
#include <windows.h>

/* Response action types */
enum class ResponseAction {
    KillProcess,
    QuarantineFile,
    RestoreFromQuarantine,
    DeleteFile,
    IsolateNetwork,
    RemoveIsolation,
};

/* Response result */
struct ResponseResult {
    bool                Success;
    ResponseAction      Action;
    std::wstring        Target;     /* PID, file path, etc. */
    std::wstring        Detail;     /* Result description */
    DWORD               ErrorCode;
};

/* Quarantine file metadata */
struct QuarantineEntry {
    std::wstring    OriginalPath;
    std::wstring    QuarantinePath;
    std::wstring    FileHash;
    std::wstring    DetectionRule;
    std::wstring    Timestamp;
    ULONG           OriginalPid;    /* Process that owned the file */
};

/* Initialize response engine */
void InitializeResponseEngine();

/* Shutdown */
void ShutdownResponseEngine();

/* Kill a process by PID (tries kernel first, falls back to user-mode) */
ResponseResult KillProcess(ULONG processId);

/* Quarantine a file - move to vault, record metadata */
ResponseResult QuarantineFile(const std::wstring& filePath, const std::wstring& rule);

/* Restore a quarantined file */
ResponseResult RestoreQuarantinedFile(const std::wstring& quarantinePath);

/* Delete a file permanently */
ResponseResult RemediateFile(const std::wstring& filePath);

/* Network isolation - block all connections except management */
ResponseResult IsolateEndpoint();

/* Remove network isolation */
ResponseResult RemoveEndpointIsolation();

/* Get all quarantined files */
std::vector<QuarantineEntry> GetQuarantinedFiles();

/* Check if endpoint is isolated */
bool IsEndpointIsolated();

/* Get response history */
std::vector<ResponseResult> GetResponseHistory(int limit = 50);

#endif /* RESPONSE_ENGINE_H */
