/*
 * EventBuffer.c -- the central event queue between kernel callbacks and the agent.
 *
 * Every callback (process, thread, image, registry, object, file) pushes
 * events here. The agent drains them via IOCTL_EDR_READ_EVENTS. It's a
 * linked list protected by a spinlock -- simple, bounded, and safe at
 * any IRQL up to DISPATCH_LEVEL.
 *
 * If the queue fills up (EDR_MAX_EVENTS_IN_QUEUE), new events are dropped
 * rather than blocking the system. The drop counter is tracked so the
 * agent knows it missed something and can log accordingly.
 *
 * Per-type counters (process, image, thread, etc.) let the dashboard
 * show a breakdown of what's generating the most telemetry.
 */

#include "EventBuffer.h"

/* ---- Global queue state ---- */
static LIST_ENTRY       g_EventListHead;     /* Doubly-linked list of EDR_EVENT_ENTRY */
static KSPIN_LOCK       g_EventListLock;     /* Protects the list and g_EventCount */
static volatile LONG    g_EventCount = 0;    /* Current entries in the queue */
static volatile LONG    g_SequenceNumber = 0;/* Monotonic counter for event ordering */
static volatile LONG    g_TotalGenerated = 0;/* Total events pushed (including dropped) */
static volatile LONG    g_TotalDelivered = 0;/* Total events successfully drained by agent */
static volatile LONG    g_EventsDropped = 0; /* Events lost because queue was full */

/* Per-type counters -- used by EDR_STATISTICS / dashboard */
static volatile LONG    g_ProcessEvents = 0;
static volatile LONG    g_ImageEvents = 0;
static volatile LONG    g_ThreadEvents = 0;
static volatile LONG    g_RegistryEvents = 0;
static volatile LONG    g_FileEvents = 0;
static volatile LONG    g_HandleEvents = 0;

static LARGE_INTEGER    g_UptimeStart = { 0 }; /* Timestamp when buffer was initialized */
static BOOLEAN          g_Initialized = FALSE;


/* Set up the list head, spinlock, and zero all counters.
   Called once from DriverEntry before any callbacks are registered. */
NTSTATUS InitializeEventBuffer(VOID)
{
    InitializeListHead(&g_EventListHead);
    KeInitializeSpinLock(&g_EventListLock);
    
    g_EventCount = 0;
    g_SequenceNumber = 0;
    g_TotalGenerated = 0;
    g_TotalDelivered = 0;
    g_EventsDropped = 0;
    g_ProcessEvents = 0;
    g_ImageEvents = 0;
    g_ThreadEvents = 0;
    g_RegistryEvents = 0;
    g_FileEvents = 0;
    g_HandleEvents = 0;

    KeQuerySystemTimePrecise(&g_UptimeStart);
    g_Initialized = TRUE;

    DbgPrint("[ VettaiyanDriver ] Event buffer initialized (max %d events)\n", EDR_MAX_EVENTS_IN_QUEUE);
    return STATUS_SUCCESS;
}


/* Drain and free every entry still in the queue.
   Called from DriverUnload -- must happen before IoDeleteDevice
   since callbacks may still be firing until we unregister them. */
VOID CleanupEventBuffer(VOID)
{
    KIRQL oldIrql;
    LIST_ENTRY localHead;
    
    if (!g_Initialized) return;

    InitializeListHead(&localHead);

    /* Splice the entire list to a local head in O(1), then release.
       This way we don't hold the lock while freeing pool memory. */
    KeAcquireSpinLock(&g_EventListLock, &oldIrql);

    if (!IsListEmpty(&g_EventListHead)) {
        localHead.Flink = g_EventListHead.Flink;
        localHead.Blink = g_EventListHead.Blink;
        localHead.Flink->Blink = &localHead;
        localHead.Blink->Flink = &localHead;
        InitializeListHead(&g_EventListHead);
    }

    g_EventCount = 0;
    g_Initialized = FALSE;

    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    /* Now free everything outside the lock -- no contention */
    while (!IsListEmpty(&localHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&localHead);
        EDR_EVENT_ENTRY* eventEntry = CONTAINING_RECORD(entry, EDR_EVENT_ENTRY, ListEntry);
        ExFreePoolWithTag(eventEntry, 'tveE');
    }

    DbgPrint("[ VettaiyanDriver ] Event buffer cleaned up. Generated=%d Delivered=%d Dropped=%d\n",
        g_TotalGenerated, g_TotalDelivered, g_EventsDropped);
}


/* Returns a unique, monotonically increasing sequence number.
   Every event gets one so the agent can detect gaps (dropped events)
   and reconstruct the exact order of operations. */
ULONG GetNextSequenceNumber(VOID)
{
    return (ULONG)InterlockedIncrement(&g_SequenceNumber);
}


/* Bump the right per-type counter based on event type.
   These feed into GetEventStatistics for the dashboard. */
static VOID IncrementTypeCounter(EDR_EVENT_TYPE type)
{
    switch (type) {
    case EdrEventProcessCreate:
    case EdrEventProcessTerminate:
        InterlockedIncrement(&g_ProcessEvents);
        break;
    case EdrEventImageLoad:
        InterlockedIncrement(&g_ImageEvents);
        break;
    case EdrEventThreadCreate:
    case EdrEventThreadTerminate:
        InterlockedIncrement(&g_ThreadEvents);
        break;
    case EdrEventRegistrySetValue:
    case EdrEventRegistryDeleteValue:
    case EdrEventRegistryDeleteKey:
    case EdrEventRegistryRenameKey:
    case EdrEventRegistryCreateKey:
        InterlockedIncrement(&g_RegistryEvents);
        break;
    case EdrEventFileCreate:
    case EdrEventFileWrite:
    case EdrEventFileDelete:
    case EdrEventFileRename:
    case EdrEventFileClose:
        InterlockedIncrement(&g_FileEvents);
        break;
    case EdrEventHandleCreate:
    case EdrEventHandleDuplicate:
        InterlockedIncrement(&g_HandleEvents);
        break;
    default:
        break;
    }
}


/*
 * PushEvent -- queue an event from any callback.
 *
 * Allocates an EDR_EVENT_ENTRY from NonPagedPool, copies the event
 * data into it, and appends to the tail of the list under the spinlock.
 * If the queue is at capacity, drops the event and bumps the counter.
 *
 * Can be called at IRQL <= DISPATCH_LEVEL (spinlock requirement).
 */
NTSTATUS PushEvent(
    _In_ PVOID EventData,
    _In_ ULONG EventSize
)
{
    EDR_EVENT_ENTRY* entry;
    KIRQL oldIrql;
    EDR_EVENT_HEADER* header;

    if (!g_Initialized || EventData == NULL || EventSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Reject oversized events -- shouldn't happen, but guard against it */
    if (EventSize > EDR_MAX_EVENT_DATA_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    /* If the queue is full, drop the event. We never block kernel
       callbacks -- better to lose telemetry than hang the system. */
    if (g_EventCount >= (LONG)EDR_MAX_EVENTS_IN_QUEUE) {
        InterlockedIncrement(&g_EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Allocate from NonPagedPool -- we may be at DISPATCH_LEVEL */
    entry = (EDR_EVENT_ENTRY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EDR_EVENT_ENTRY),
        'tveE'
    );

    if (entry == NULL) {
        InterlockedIncrement(&g_EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Copy event data into the pool-allocated entry */
    RtlZeroMemory(entry, sizeof(EDR_EVENT_ENTRY));
    entry->DataSize = EventSize;
    RtlCopyMemory(entry->Data, EventData, EventSize);

    /* Bump the per-type counter for dashboard stats */
    header = (EDR_EVENT_HEADER*)EventData;
    IncrementTypeCounter(header->EventType);

    /* Append to the tail under the spinlock -- only the list
       insert and count update need protection. Stats counters
       use InterlockedIncrement so they stay outside the lock. */
    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    InsertTailList(&g_EventListHead, &entry->ListEntry);
    InterlockedIncrement(&g_EventCount);
    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    InterlockedIncrement(&g_TotalGenerated);

    return STATUS_SUCCESS;
}


/*
 * DrainEvents -- called from IOCTL_EDR_READ_EVENTS handler.
 *
 * Moves entries from the global queue to a local list under the lock
 * (cheap pointer swaps), then does the expensive RtlCopyMemory and
 * ExFreePoolWithTag work AFTER releasing. This keeps lock hold time
 * proportional to pointer operations, not data size.
 *
 * The agent calls this in a polling loop. Events that don't fit
 * stay in the queue for the next call.
 */
ULONG DrainEvents(
    _Out_writes_bytes_(BufferSize) PVOID UserBuffer,
    _In_ ULONG BufferSize
)
{
    KIRQL oldIrql;
    ULONG bytesWritten = 0;
    ULONG totalSize = 0;
    LONG drainCount = 0;
    PUCHAR writePtr = (PUCHAR)UserBuffer;
    LIST_ENTRY localHead;

    if (!g_Initialized || UserBuffer == NULL || BufferSize == 0) {
        return 0;
    }

    InitializeListHead(&localHead);

    /* Phase 1: under the lock, move fitting entries to a local list.
       Only pointer swaps happen here -- no copies, no frees. */
    KeAcquireSpinLock(&g_EventListLock, &oldIrql);

    while (!IsListEmpty(&g_EventListHead)) {
        PLIST_ENTRY listEntry = g_EventListHead.Flink;
        EDR_EVENT_ENTRY* eventEntry = CONTAINING_RECORD(listEntry, EDR_EVENT_ENTRY, ListEntry);

        /* Check if this event fits in remaining buffer */
        if (totalSize + eventEntry->DataSize > BufferSize) {
            break;
        }

        /* Detach from global list, attach to local list */
        RemoveEntryList(listEntry);
        InsertTailList(&localHead, listEntry);
        totalSize += eventEntry->DataSize;
        drainCount++;
    }

    g_EventCount -= drainCount;

    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    /* Phase 2: outside the lock, do the expensive work.
       RtlCopyMemory + ExFreePoolWithTag with zero contention. */
    while (!IsListEmpty(&localHead)) {
        PLIST_ENTRY listEntry = RemoveHeadList(&localHead);
        EDR_EVENT_ENTRY* eventEntry = CONTAINING_RECORD(listEntry, EDR_EVENT_ENTRY, ListEntry);

        RtlCopyMemory(writePtr, eventEntry->Data, eventEntry->DataSize);
        writePtr += eventEntry->DataSize;
        bytesWritten += eventEntry->DataSize;
        InterlockedIncrement(&g_TotalDelivered);

        ExFreePoolWithTag(eventEntry, 'tveE');
    }

    return bytesWritten;
}


/* Snapshot the current counters into an EDR_STATISTICS struct.
   Called from IOCTL_EDR_GET_STATS -- the dashboard uses this
   to show event throughput, queue depth, and drop rate. */
VOID GetEventStatistics(
    _Out_ EDR_STATISTICS* Stats
)
{
    if (Stats == NULL) return;

    RtlZeroMemory(Stats, sizeof(EDR_STATISTICS));
    Stats->TotalEventsGenerated = (ULONG)g_TotalGenerated;
    Stats->TotalEventsDelivered = (ULONG)g_TotalDelivered;
    Stats->EventsDropped = (ULONG)g_EventsDropped;
    Stats->QueueDepth = (ULONG)g_EventCount;
    Stats->ProcessEventsCount = (ULONG)g_ProcessEvents;
    Stats->ImageEventsCount = (ULONG)g_ImageEvents;
    Stats->ThreadEventsCount = (ULONG)g_ThreadEvents;
    Stats->RegistryEventsCount = (ULONG)g_RegistryEvents;
    Stats->FileEventsCount = (ULONG)g_FileEvents;
    Stats->HandleEventsCount = (ULONG)g_HandleEvents;
    Stats->UptimeStart = g_UptimeStart;
}
