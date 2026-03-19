/*
 * EventReceiver.h - Kernel event receiver for VettaiyanAgent
 * 
 * Connects to VettaiyanDriver (via IOCTL) and VettaiyanFilter (via FilterPort)
 * to receive real-time kernel telemetry events.
 */

#ifndef EVENT_RECEIVER_H
#define EVENT_RECEIVER_H

#include <string>
#include <vector>
#include <functional>
#include <windows.h>
#include <fltuser.h>

#pragma comment(lib, "fltlib.lib")

#include "../EdrCommon/EdrEvents.h"

/* Callback type for processing events */
typedef std::function<void(const EDR_EVENT_HEADER* header, const void* eventData, ULONG eventSize)> EventCallback;

/* Initialize the event receiver - connects to both drivers */
bool InitializeEventReceiver();

/* Shutdown the event receiver */
void ShutdownEventReceiver();

/* Register a callback to receive events */
void RegisterEventCallback(EventCallback callback);

/* Get driver statistics */
bool GetDriverStatistics(EDR_STATISTICS* stats);

/* Send a kill-process command to the driver */
bool KillProcessViaDriver(ULONG processId, ULONG reason);

/* Check if driver connection is active */
bool IsDriverConnected();

/* Check if filter connection is active */
bool IsFilterConnected();

#endif /* EVENT_RECEIVER_H */
