/*
 * FilterCommPort.c — Filter communication port implementation.
 *
 * Uses FltCreateCommunicationPort to establish a kernel-to-user
 * message channel between the minifilter and the VettaiyanAgent.
 * File events are sent as EDR_FILE_EVENT structs over this port.
 *
 * Lifecycle:
 *   1. InitializeFilterCommPort()  — creates the server port (called after FltRegisterFilter)
 *   2. Agent connects              — FilterConnectNotify() stores the client port handle
 *   3. SendFileEventToAgent()      — pushes events to the agent (with timeout)
 *   4. Agent disconnects           — FilterDisconnectNotify() clears the client port
 *   5. CleanupFilterCommPort()     — tears down server + client ports (called before FltUnregisterFilter)
 */

#include "FsFilter.h"

/* Global port handles — only one agent connection at a time (see FS_MAX_CONNECTIONS) */
static PFLT_PORT   g_ServerPort = NULL;    /* Listening end (kernel owns this) */
static PFLT_PORT   g_ClientPort = NULL;    /* Connected agent handle */
static PFLT_FILTER g_FilterHandle = NULL;  /* Cached filter handle for FltSendMessage */

/* PID of the connected agent — used to skip our own I/O in callbacks. */
volatile ULONG g_AgentPid = 0;


/*
 * FilterConnectNotify — Called when the user-mode agent connects to the port.
 *
 * Stores the client port handle so subsequent SendFileEventToAgent() calls
 * can reach the agent.
 */
NTSTATUS
FilterConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID* ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    g_ClientPort = ClientPort;
    g_AgentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    *ConnectionCookie = NULL;

    KdPrint(("[ VettaiyanFilter ] Agent connected (PID %lu)\n", g_AgentPid));
    return STATUS_SUCCESS;
}


/*
 * FilterDisconnectNotify — Called when the agent disconnects (or crashes).
 *
 * Closes the client port and NULLs the handle. After this,
 * IsAgentConnected() returns FALSE and all callbacks skip sending events.
 */
VOID
FilterDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (g_ClientPort) {
        FltCloseClientPort(g_FilterHandle, &g_ClientPort);
        g_ClientPort = NULL;
    }
    g_AgentPid = 0;

    KdPrint(("[ VettaiyanFilter ] Agent disconnected from filter port\n"));
}


/*
 * FilterMessageNotify — Called when the agent sends a message to the filter.
 *
 * Currently unused — the communication is one-way (filter -> agent).
 * Reserved for future use (e.g., agent sending config updates to the filter).
 */
NTSTATUS
FilterMessageNotify(
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);

    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}


/*
 * InitializeFilterCommPort — Creates the server-side communication port.
 *
 * Must be called after FltRegisterFilter() succeeds. Sets up:
 *   - A security descriptor allowing any user to connect (Everyone: FLT_PORT_ALL_ACCESS)
 *   - The named port (EDR_FILTER_PORT_NAME from EdrEvents.h)
 *   - Connect/disconnect/message callbacks
 *   - Connection limit (FS_MAX_CONNECTIONS from FsCommon.h)
 */
NTSTATUS InitializeFilterCommPort(_In_ PFLT_FILTER FilterHandle)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    g_FilterHandle = FilterHandle;

    /* Build a default SD granting Everyone full port access */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[ VettaiyanFilter ] Failed to build security descriptor: 0x%X\n", status));
        return status;
    }

    RtlInitUnicodeString(&portName, EDR_FILTER_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    /* Create the server port — agent will connect to this name */
    status = FltCreateCommunicationPort(
        FilterHandle,
        &g_ServerPort,
        &oa,
        NULL,
        FilterConnectNotify,
        FilterDisconnectNotify,
        FilterMessageNotify,
        FS_MAX_CONNECTIONS
    );

    /* SD is no longer needed after port creation */
    FltFreeSecurityDescriptor(sd);

    if (NT_SUCCESS(status)) {
        KdPrint(("[ VettaiyanFilter ] Communication port created: %wZ\n", &portName));
    } else {
        KdPrint(("[ VettaiyanFilter ] Failed to create comm port: 0x%X\n", status));
    }

    return status;
}


/*
 * CleanupFilterCommPort — Tears down both server and client ports.
 *
 * Called during filter unload. Closes the client port first (disconnects
 * the agent), then closes the server port (stops accepting connections).
 */
VOID CleanupFilterCommPort(VOID)
{
    if (g_ClientPort) {
        FltCloseClientPort(g_FilterHandle, &g_ClientPort);
        g_ClientPort = NULL;
    }
    g_AgentPid = 0;

    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

    KdPrint(("[ VettaiyanFilter ] Communication port cleaned up\n"));
}


/*
 * IsAgentConnected — Quick check used by all callbacks to skip event
 * processing when no agent is listening.
 */
BOOLEAN IsAgentConnected(VOID)
{
    return (g_ClientPort != NULL) ? TRUE : FALSE;
}


/*
 * SendFileEventToAgent — Sends a single file event to the connected agent.
 *
 * Uses FltSendMessage with a bounded timeout (FS_SEND_TIMEOUT_100NS)
 * to avoid blocking I/O indefinitely if the agent is slow. Returns
 * STATUS_PORT_DISCONNECTED if no agent is connected.
 */
NTSTATUS SendFileEventToAgent(
    _In_ EDR_FILE_EVENT* FileEvent
)
{
    NTSTATUS status;
    ULONG replyLength = 0;
    LARGE_INTEGER timeout;

    /* Bail early if no agent or NULL event */
    if (g_ClientPort == NULL || FileEvent == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    /* Bounded timeout to prevent blocking filesystem I/O.
       See FS_SEND_TIMEOUT_100NS in FsCommon.h to adjust. */
    timeout.QuadPart = FS_SEND_TIMEOUT_100NS;

    status = FltSendMessage(
        g_FilterHandle,
        &g_ClientPort,
        FileEvent,
        sizeof(EDR_FILE_EVENT),
        NULL,           /* No reply buffer — one-way message */
        &replyLength,
        &timeout
    );

    return status;
}
