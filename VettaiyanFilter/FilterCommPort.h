/*
 * FilterCommPort.h -- how the filter talks to the agent.
 * One named port, one connection at a time.
 */

#ifndef FILTER_COMM_PORT_H
#define FILTER_COMM_PORT_H

#include "DriverHeader.h"

/* Create the port. Call this right after FltRegisterFilter. */
NTSTATUS InitializeFilterCommPort(_In_ PFLT_FILTER FilterHandle);

/* Shut the port down. Call before FltUnregisterFilter. */
VOID CleanupFilterCommPort(VOID);

/* Send a file event to the agent. Does nothing if nobody's connected. */
NTSTATUS SendFileEventToAgent(_In_ EDR_FILE_EVENT* FileEvent);

/* Quick check -- is the agent currently talking to us? */
BOOLEAN IsAgentConnected(VOID);

#endif /* FILTER_COMM_PORT_H */
