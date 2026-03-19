/*
 * EdrEvents.h - Shared event definitions for Vettaiyan EDR
 * 
 * Used by: VettaiyanDriver (kernel), VettaiyanFilter (kernel), VettaiyanAgent (user)
 * Defines the common event protocol between kernel sensors and user-mode agent.
 */

#ifndef EDR_EVENTS_H
#define EDR_EVENTS_H

/* Detect kernel mode: ntifs.h defines _NTIFS_, ntddk.h defines _NTDDK_ */
#if defined(_NTIFS_) || defined(_NTDDK_) || defined(_KERNEL_MODE)
  #define EDR_KERNEL_MODE 1
#endif

#ifdef EDR_KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
#endif

/* ============================================================
 *  IOCTL Codes - Driver <-> Agent communication
 * ============================================================ */

#define EDR_DEVICE_TYPE         FILE_DEVICE_UNKNOWN

#define IOCTL_EDR_READ_EVENTS       CTL_CODE(EDR_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_EDR_GET_STATS         CTL_CODE(EDR_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_EDR_KILL_PROCESS      CTL_CODE(EDR_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* ============================================================
 *  Event Types
 * ============================================================ */

typedef enum _EDR_EVENT_TYPE {
    EdrEventNone = 0,

    // Process events
    EdrEventProcessCreate       = 1,
    EdrEventProcessTerminate    = 2,

    // Image/DLL events
    EdrEventImageLoad           = 10,

    // Thread events
    EdrEventThreadCreate        = 20,
    EdrEventThreadTerminate     = 21,

    // Registry events
    EdrEventRegistrySetValue    = 30,
    EdrEventRegistryDeleteValue = 31,
    EdrEventRegistryDeleteKey   = 32,
    EdrEventRegistryRenameKey   = 33,
    EdrEventRegistryCreateKey   = 34,

    // Filesystem events
    EdrEventFileCreate          = 40,
    EdrEventFileWrite           = 41,
    EdrEventFileDelete          = 42,
    EdrEventFileRename          = 43,
    EdrEventFileClose           = 44,

    // Handle/Object events
    EdrEventHandleCreate        = 50,
    EdrEventHandleDuplicate     = 51,

} EDR_EVENT_TYPE;

/* ============================================================
 *  Severity Levels
 * ============================================================ */

typedef enum _EDR_SEVERITY {
    EdrSeverityInfo       = 0,
    EdrSeverityLow        = 1,
    EdrSeverityMedium     = 2,
    EdrSeverityHigh       = 3,
    EdrSeverityCritical   = 4,
} EDR_SEVERITY;

/* ============================================================
 *  Event Structures - Fixed-size for ring buffer efficiency
 * ============================================================ */

#define EDR_MAX_PATH        520
#define EDR_MAX_CMDLINE     1024
#define EDR_MAX_REGPATH     512
#define EDR_MAX_REGVALUE    256

/* Extensions the agent should prioritize for YARA scanning.
   The filter sends ALL close events -- the agent checks this list.
   Add new types here as needed. */
static const wchar_t* EDR_SCAN_EXTENSIONS[] = {
    L"exe",   /* PE executables */
    L"dll",   /* Dynamic libraries */
    L"sys",   /* Kernel drivers */
    L"bat",   /* Batch scripts */
    L"cmd",   /* Command scripts */
    L"ps1",   /* PowerShell scripts */
    L"vbs",   /* VBScript */
    L"js",    /* JScript / Node */
    L"msi",   /* Windows installers */
    L"scr",   /* Screensavers (PE) */
    L"hta",   /* HTML applications */
    L"wsf",   /* Windows Script Files */
    L"py",    /* Python scripts */
    L"docm",  /* Macro-enabled docs */
    L"xlsm",  /* Macro-enabled sheets */
};
#define EDR_SCAN_EXTENSION_COUNT (sizeof(EDR_SCAN_EXTENSIONS) / sizeof(EDR_SCAN_EXTENSIONS[0]))

/* Common header for all events */
typedef struct _EDR_EVENT_HEADER {
    EDR_EVENT_TYPE  EventType;
    LARGE_INTEGER   Timestamp;
    ULONG           ProcessId;
    ULONG           ThreadId;
    ULONG           EventSize;      // Total size of this event including header
    ULONG           SequenceNumber; // Monotonically increasing
} EDR_EVENT_HEADER;

/* Process create/terminate event */
typedef struct _EDR_PROCESS_EVENT {
    EDR_EVENT_HEADER Header;
    ULONG   ParentProcessId;
    ULONG   SessionId;
    LUID    AuthenticationId;   // Logon session -- agent calls LsaGetLogonSessionData to get LogonType
    WCHAR   ImagePath[EDR_MAX_PATH];
    WCHAR   ParentImagePath[EDR_MAX_PATH];
    WCHAR   CommandLine[EDR_MAX_CMDLINE];
} EDR_PROCESS_EVENT;

/* Image/DLL load event */
typedef struct _EDR_IMAGE_EVENT {
    EDR_EVENT_HEADER Header;
    ULONG_PTR   ImageBase;
    SIZE_T      ImageSize;
    WCHAR       ImagePath[EDR_MAX_PATH];
    WCHAR       ProcessImagePath[EDR_MAX_PATH];
} EDR_IMAGE_EVENT;

/* Thread create/terminate event */
typedef struct _EDR_THREAD_EVENT {
    EDR_EVENT_HEADER Header;
    ULONG   TargetProcessId;
    ULONG   TargetThreadId;
    BOOLEAN IsRemoteThread;     // Thread in different process
} EDR_THREAD_EVENT;

/* Registry operation event */
typedef struct _EDR_REGISTRY_EVENT {
    EDR_EVENT_HEADER Header;
    WCHAR   KeyPath[EDR_MAX_REGPATH];
    WCHAR   ValueName[EDR_MAX_REGVALUE];
} EDR_REGISTRY_EVENT;

/* File operation event */
typedef struct _EDR_FILE_EVENT {
    EDR_EVENT_HEADER Header;
    WCHAR           FilePath[EDR_MAX_PATH];
    WCHAR           NewFilePath[EDR_MAX_PATH];  // For rename operations
    LARGE_INTEGER   FileSize;
    ULONG           FileAttributes;
    ULONG           CreateDisposition;  // FILE_CREATED, FILE_OPENED, FILE_OVERWRITTEN, etc.
} EDR_FILE_EVENT;

/* Handle/Object operation event */
typedef struct _EDR_HANDLE_EVENT {
    EDR_EVENT_HEADER Header;
    ULONG       TargetProcessId;
    ULONG       TargetThreadId;     // Non-zero for thread handle ops
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK OriginalAccess;
} EDR_HANDLE_EVENT;

/* ============================================================
 *  Statistics structure (read via IOCTL_EDR_GET_STATS)
 * ============================================================ */

typedef struct _EDR_STATISTICS {
    ULONG       TotalEventsGenerated;
    ULONG       TotalEventsDelivered;
    ULONG       EventsDropped;
    ULONG       QueueDepth;
    ULONG       ProcessEventsCount;
    ULONG       ImageEventsCount;
    ULONG       ThreadEventsCount;
    ULONG       RegistryEventsCount;
    ULONG       FileEventsCount;
    ULONG       HandleEventsCount;
    LARGE_INTEGER UptimeStart;
} EDR_STATISTICS;

/* ============================================================
 *  Kill process request (via IOCTL_EDR_KILL_PROCESS)
 * ============================================================ */

typedef struct _EDR_KILL_PROCESS_REQUEST {
    ULONG   ProcessId;
    ULONG   Reason;     // 0 = manual, 1 = behavioral, 2 = YARA match
} EDR_KILL_PROCESS_REQUEST;

/* ============================================================
 *  Filter Communication Port definitions
 * ============================================================ */

#define EDR_FILTER_PORT_NAME    L"\\VettaiyanFilterPort"

/* Filter user-mode message/reply structures - only available in user mode */
#ifndef EDR_KERNEL_MODE
#include <fltUser.h>

typedef struct _EDR_FILTER_MESSAGE {
    FILTER_MESSAGE_HEADER   MessageHeader;
    EDR_FILE_EVENT          FileEvent;
} EDR_FILTER_MESSAGE;

typedef struct _EDR_FILTER_REPLY {
    FILTER_REPLY_HEADER     ReplyHeader;
    BOOLEAN                 Block;
} EDR_FILTER_REPLY;

#endif /* !EDR_KERNEL_MODE */

/* ============================================================
 *  Event buffer parameters
 * ============================================================ */

#define EDR_MAX_EVENTS_IN_QUEUE     2048
#define EDR_MAX_EVENT_DATA_SIZE     sizeof(EDR_PROCESS_EVENT) // Largest event type

#endif /* EDR_EVENTS_H */
