/*
 * TelemetryDb.h - Telemetry event persistence
 *
 * Stores kernel events, behavioral detections, and ETW events
 * in SQLite for the UI to query (timeline, analytics).
 */

#ifndef TELEMETRY_DB_H
#define TELEMETRY_DB_H

#include <string>
#include <windows.h>
#include "../EdrCommon/EdrEvents.h"
#include "BehaviorEngine.h"

/* Initialize telemetry database (creates tables if needed) */
bool InitializeTelemetryDb();

/* Shutdown */
void ShutdownTelemetryDb();

/* Store a kernel event */
void StoreKernelEvent(const EDR_EVENT_HEADER* header, const std::wstring& detail);

/* Store a behavioral detection */
void StoreBehaviorDetection(const BehaviorDetection& detection);

/* Store an ETW event */
void StoreEtwEvent(const std::wstring& type, ULONG pid, const std::wstring& detail);

/* Get total event count */
int GetTelemetryEventCount();

/* Get total behavioral detection count */
int GetBehaviorDetectionCount();

#endif /* TELEMETRY_DB_H */
