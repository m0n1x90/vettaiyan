#ifndef FS_COMMON_H
#define FS_COMMON_H

/*
 * FsCommon.h -- numbers you can tweak without touching real code.
 * All the thresholds and limits for the minifilter live here.
 */

/* Smallest write (in bytes) we care about. Anything below this
   is usually NTFS journal chatter. 32 is low enough to catch
   tiny shellcode stagers. */
#define FS_MIN_WRITE_SIZE           32

/* Paths shorter than this (bytes) are internal handles, not real files. */
#define FS_MIN_PATH_LENGTH          20

/* Stack buffer size for path matching (in WCHARs). Keep this
   at least as big as EDR_MAX_PATH (520). */
#define FS_PATH_BUFFER_LEN          520

/* How many agents can connect to the filter port at once. */
#define FS_MAX_CONNECTIONS          1

/* How long to wait when sending a message to the agent.
   100ns units, negative means relative. -1000000 = 100ms.
   Increase if the agent is under heavy load. */
#define FS_SEND_TIMEOUT_100NS       (-1000000LL)

#include "DriverHeader.h"

/* The agent's PID, captured when it connects to our port.
   0 when no agent is connected. Every callback checks this
   to skip its own I/O and avoid feedback loops. */
extern volatile ULONG g_AgentPid;

/* Should we ignore this file event? Returns TRUE for our own
   agent PID, kernel threads, and other non-interesting stuff. */
BOOLEAN ShouldExcludePath(_In_ PFLT_FILE_NAME_INFORMATION FileNameInfo);

#endif /* FS_COMMON_H */
