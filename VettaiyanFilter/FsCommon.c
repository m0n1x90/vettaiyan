/*
 * FsCommon.c -- exclusion logic and shared state for the filter.
 *
 * Every callback runs ShouldExcludePath() before sending an event.
 * Self-exclusion is PID-based (g_AgentPid, set when the agent connects)
 * so attackers can't bypass it by naming files after us.
 *
 * Thresholds live in FsCommon.h.
 */

#include "FsFilter.h"

/* Sequence counter shared across all callbacks. */
volatile LONG g_FilterSequence = 0;


/*
 * ShouldExcludePath -- top-level check used by all callbacks.
 * Returns TRUE if the event should be dropped.
 *
 * Exclusions (all non-spoofable):
 *   - NULL / empty path
 *   - PID 0, 4 (System Idle, System)
 *   - Agent's own PID (prevents feedback loop)
 */
BOOLEAN ShouldExcludePath(_In_ PFLT_FILE_NAME_INFORMATION FileNameInfo)
{
    if (!FileNameInfo || FileNameInfo->Name.Length == 0) return TRUE;

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    /* Kernel threads -- pure system I/O, not user-initiated */
    if (pid == 0 || pid == 4) return TRUE;

    /* Our own agent -- PID captured when it connected to the port */
    if (g_AgentPid != 0 && pid == g_AgentPid) return TRUE;

    return FALSE;
}
