/*
 * EtwConsumer.cpp - ETW trace session consumer
 * 
 * Subscribes to kernel ETW providers for network, DNS, and PowerShell
 * telemetry. Events are normalized and dispatched to registered callbacks.
 * 
 * Uses the TDH (Trace Data Helper) API for event parsing.
 */

#include "EtwConsumer.h"
#include "Log.h"

#define INITGUID
#include <guiddef.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#include <mutex>
#include <deque>
#include <vector>

/* ETW Provider GUIDs */
/* Microsoft-Windows-Kernel-Network */
DEFINE_GUID(KERNEL_NETWORK_GUID,
    0x7dd42a49, 0x5329, 0x4832, 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88);

/* Microsoft-Windows-DNS-Client */
DEFINE_GUID(DNS_CLIENT_GUID,
    0x1c95126e, 0x7eea, 0x49a9, 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d);

/* Microsoft-Windows-PowerShell */
DEFINE_GUID(POWERSHELL_GUID,
    0xa0c1853b, 0x5c40, 0x4b15, 0x87, 0x66, 0x3c, 0xf1, 0xc5, 0x8f, 0x98, 0x5a);


#define SESSION_NAME L"VettaiyanEtwSession"

static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_ProcessThread = NULL;
static HANDLE g_StopEvent = NULL;

static std::vector<EtwEventCallback> g_EtwCallbacks;
static std::deque<EtwEvent> g_NetworkEvents;
static std::deque<EtwEvent> g_DnsEvents;
static std::mutex g_EtwMutex;
static const size_t MAX_ETW_EVENTS = 5000;


static void StoreAndDispatch(const EtwEvent& event)
{
    {
        std::lock_guard<std::mutex> lock(g_EtwMutex);
        switch (event.Type) {
        case EtwEventType::NetworkConnect:
        case EtwEventType::NetworkDisconnect:
            g_NetworkEvents.push_back(event);
            if (g_NetworkEvents.size() > MAX_ETW_EVENTS) g_NetworkEvents.pop_front();
            break;
        case EtwEventType::DnsQuery:
            g_DnsEvents.push_back(event);
            if (g_DnsEvents.size() > MAX_ETW_EVENTS) g_DnsEvents.pop_front();
            break;
        default:
            break;
        }
    }

    for (auto& cb : g_EtwCallbacks) {
        cb(event);
    }
}


static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
{
    if (!pEvent) return;

    EtwEvent evt = {};
    evt.ProcessId = pEvent->EventHeader.ProcessId;
    evt.Timestamp = *(FILETIME*)&pEvent->EventHeader.TimeStamp;

    /* Identify provider */
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, KERNEL_NETWORK_GUID)) {
        /* Network events: Opcode 10 = TCP/IP send, 11 = TCP/IP receive, 12 = connect, 15 = disconnect */
        USHORT opcode = pEvent->EventHeader.EventDescriptor.Opcode;
        if (opcode == 12) {
            evt.Type = EtwEventType::NetworkConnect;
            evt.Detail = L"TCP Connect from PID " + std::to_wstring(evt.ProcessId);
            StoreAndDispatch(evt);
        } else if (opcode == 15) {
            evt.Type = EtwEventType::NetworkDisconnect;
            evt.Detail = L"TCP Disconnect from PID " + std::to_wstring(evt.ProcessId);
            StoreAndDispatch(evt);
        }
    }
    else if (IsEqualGUID(pEvent->EventHeader.ProviderId, DNS_CLIENT_GUID)) {
        evt.Type = EtwEventType::DnsQuery;
        
        /* Parse DNS query name from event data using TDH */
        DWORD bufferSize = 0;
        TDHSTATUS status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0) {
            std::vector<BYTE> buffer(bufferSize);
            PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)buffer.data();
            
            status = TdhGetEventInformation(pEvent, 0, NULL, info, &bufferSize);
            if (status == ERROR_SUCCESS && info->TopLevelPropertyCount > 0) {
                /* First property is usually the query name */
                PROPERTY_DATA_DESCRIPTOR dataDesc = {};
                dataDesc.PropertyName = (ULONGLONG)((PBYTE)info + info->EventPropertyInfoArray[0].NameOffset);
                dataDesc.ArrayIndex = ULONG_MAX;

                DWORD propertySize = 0;
                TdhGetPropertySize(pEvent, 0, NULL, 1, &dataDesc, &propertySize);
                if (propertySize > 0 && propertySize < 2048) {
                    std::vector<BYTE> propBuffer(propertySize);
                    if (TdhGetProperty(pEvent, 0, NULL, 1, &dataDesc, propertySize, propBuffer.data()) == ERROR_SUCCESS) {
                        evt.QueryName = (LPCWSTR)propBuffer.data();
                    }
                }
            }
        }

        if (!evt.QueryName.empty()) {
            evt.Detail = L"DNS Query: " + evt.QueryName;
        } else {
            evt.Detail = L"DNS Query from PID " + std::to_wstring(evt.ProcessId);
        }
        StoreAndDispatch(evt);
    }
    else if (IsEqualGUID(pEvent->EventHeader.ProviderId, POWERSHELL_GUID)) {
        /* PowerShell script block logging - Event ID 4104 */
        if (pEvent->EventHeader.EventDescriptor.Id == 4104) {
            evt.Type = EtwEventType::PowerShellCommand;
            evt.Detail = L"PowerShell ScriptBlock from PID " + std::to_wstring(evt.ProcessId);
            StoreAndDispatch(evt);
        }
    }
}


static ULONG WINAPI BufferCallback(PEVENT_TRACE_LOGFILEW pLog)
{
    UNREFERENCED_PARAMETER(pLog);
    /* Return TRUE to continue processing */
    if (g_StopEvent && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0) {
        return FALSE; /* Stop processing */
    }
    return TRUE;
}


static DWORD WINAPI EtwProcessThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    EVENT_TRACE_LOGFILEW traceLog = {};
    traceLog.LoggerName = (LPWSTR)SESSION_NAME;
    traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLog.EventRecordCallback = EventRecordCallback;
    traceLog.BufferCallback = BufferCallback;

    g_TraceHandle = OpenTraceW(&traceLog);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LogMessage(L"[ EtwConsumer ] Failed to open trace, error: " + std::to_wstring(GetLastError()));
        return 1;
    }

    /* This blocks until the session is stopped */
    ULONG status = ProcessTrace(&g_TraceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        LogMessage(L"[ EtwConsumer ] ProcessTrace ended with error: " + std::to_wstring(status));
    }

    return 0;
}


bool InitializeEtwConsumer()
{
    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) return false;

    /* Calculate buffer size for trace properties */
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(WCHAR);
    std::vector<BYTE> buffer(bufferSize, 0);
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)buffer.data();

    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; /* QPC for timestamps */
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    /* Stop any existing session with same name */
    ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    /* Start new session */
    ULONG status = StartTraceW(&g_SessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        LogMessage(L"[ EtwConsumer ] Failed to start trace session: " + std::to_wstring(status));
        /* Non-fatal - ETW requires admin, may not be available */
        return false;
    }

    /* Enable Network provider */
    status = EnableTraceEx2(g_SessionHandle, &KERNEL_NETWORK_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        LogMessage(L"[ EtwConsumer ] Failed to enable Network provider: " + std::to_wstring(status));
    }

    /* Enable DNS provider */
    status = EnableTraceEx2(g_SessionHandle, &DNS_CLIENT_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        LogMessage(L"[ EtwConsumer ] Failed to enable DNS provider: " + std::to_wstring(status));
    }

    /* Enable PowerShell provider */
    status = EnableTraceEx2(g_SessionHandle, &POWERSHELL_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        LogMessage(L"[ EtwConsumer ] Failed to enable PowerShell provider: " + std::to_wstring(status));
    }

    /* Start processing thread */
    g_ProcessThread = CreateThread(NULL, 0, EtwProcessThread, NULL, 0, NULL);
    if (!g_ProcessThread) {
        LogMessage(L"[ EtwConsumer ] Failed to create ETW process thread");
        return false;
    }

    LogMessage(L"[ EtwConsumer ] ETW session started - Network, DNS, PowerShell providers enabled");
    return true;
}


void ShutdownEtwConsumer()
{
    if (g_StopEvent) SetEvent(g_StopEvent);

    if (g_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_TraceHandle);
        g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (g_SessionHandle) {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(WCHAR);
        std::vector<BYTE> buffer(bufferSize, 0);
        PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)buffer.data();
        props->Wnode.BufferSize = bufferSize;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(g_SessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        g_SessionHandle = 0;
    }

    if (g_ProcessThread) {
        WaitForSingleObject(g_ProcessThread, 5000);
        CloseHandle(g_ProcessThread);
        g_ProcessThread = NULL;
    }

    if (g_StopEvent) {
        CloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }

    std::lock_guard<std::mutex> lock(g_EtwMutex);
    g_EtwCallbacks.clear();
    g_NetworkEvents.clear();
    g_DnsEvents.clear();

    LogMessage(L"[ EtwConsumer ] Shutdown complete");
}


void RegisterEtwCallback(EtwEventCallback callback)
{
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    g_EtwCallbacks.push_back(callback);
}


std::vector<EtwEvent> GetRecentNetworkEvents(int limit)
{
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    std::vector<EtwEvent> result;
    int count = 0;
    for (auto it = g_NetworkEvents.rbegin(); it != g_NetworkEvents.rend() && count < limit; ++it, ++count) {
        result.push_back(*it);
    }
    return result;
}


std::vector<EtwEvent> GetRecentDnsEvents(int limit)
{
    std::lock_guard<std::mutex> lock(g_EtwMutex);
    std::vector<EtwEvent> result;
    int count = 0;
    for (auto it = g_DnsEvents.rbegin(); it != g_DnsEvents.rend() && count < limit; ++it, ++count) {
        result.push_back(*it);
    }
    return result;
}
