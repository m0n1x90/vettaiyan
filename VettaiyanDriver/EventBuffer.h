/*
 * EventBuffer.h -- kernel-to-agent event queue.
 *
 * All kernel callbacks push events here via PushEvent(). The agent
 * drains them via IOCTL_EDR_READ_EVENTS. Bounded queue -- drops
 * events when full rather than blocking kernel operations.
 *
 * Thread-safe at any IRQL up to DISPATCH_LEVEL (spinlock-protected).
 */

#ifndef EVENT_BUFFER_H
#define EVENT_BUFFER_H

#include "DriverHeader.h"
#include "../EdrCommon/EdrEvents.h"

/* One entry in the queue -- list node + raw event bytes */
typedef struct _EDR_EVENT_ENTRY {
    LIST_ENTRY  ListEntry;                  /* Doubly-linked list pointers */
    ULONG       DataSize;                   /* Actual size of event data */
    UCHAR       Data[EDR_MAX_EVENT_DATA_SIZE]; /* Raw event (process, thread, etc.) */
} EDR_EVENT_ENTRY;

/* Called once from DriverEntry -- sets up the list and spinlock */
NTSTATUS InitializeEventBuffer(VOID);

/* Called from DriverUnload -- frees all remaining entries */
VOID CleanupEventBuffer(VOID);

/* Queue an event from any callback. Drops if queue is full. */
NTSTATUS PushEvent(
    _In_ PVOID EventData,
    _In_ ULONG EventSize
);

/* Copy events into the agent's buffer. Returns bytes written.
   Called from the IOCTL_EDR_READ_EVENTS handler. */
ULONG DrainEvents(
    _Out_writes_bytes_(BufferSize) PVOID UserBuffer,
    _In_ ULONG BufferSize
);

/* Snapshot current counters for the dashboard */
VOID GetEventStatistics(
    _Out_ EDR_STATISTICS* Stats
);

/* Monotonic sequence number -- every event gets a unique one
   so the agent can detect gaps from dropped events */
ULONG GetNextSequenceNumber(VOID);

#endif /* EVENT_BUFFER_H */
