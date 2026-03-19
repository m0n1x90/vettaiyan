/*
 * EtwConsumer.h - ETW (Event Tracing for Windows) consumer
 *
 * Consumes Microsoft kernel ETW providers for:
 * - Network connections (Microsoft-Windows-Kernel-Network)
 * - DNS queries (Microsoft-Windows-DNS-Client)
 * - PowerShell activity (Microsoft-Windows-PowerShell)
 */

#ifndef ETW_CONSUMER_H
#define ETW_CONSUMER_H

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

/* ETW event types */
enum class EtwEventType {
    NetworkConnect,
    NetworkDisconnect,
    DnsQuery,
    PowerShellCommand,
};

/* Normalized ETW event */
struct EtwEvent {
    EtwEventType    Type;
    ULONG           ProcessId;
    FILETIME        Timestamp;
    std::wstring    Detail;         /* Human-readable description */
    
    /* Network-specific */
    std::wstring    SourceAddress;
    USHORT          SourcePort;
    std::wstring    DestAddress;
    USHORT          DestPort;
    std::wstring    Protocol;

    /* DNS-specific */
    std::wstring    QueryName;
    std::wstring    QueryResult;

    /* PowerShell-specific */
    std::wstring    ScriptBlock;
};

typedef std::function<void(const EtwEvent& event)> EtwEventCallback;

/* Start ETW tracing session */
bool InitializeEtwConsumer();

/* Stop ETW tracing and cleanup */
void ShutdownEtwConsumer();

/* Register callback for ETW events */
void RegisterEtwCallback(EtwEventCallback callback);

/* Get recent network events */
std::vector<EtwEvent> GetRecentNetworkEvents(int limit = 50);

/* Get recent DNS queries */
std::vector<EtwEvent> GetRecentDnsEvents(int limit = 50);

#endif /* ETW_CONSUMER_H */
