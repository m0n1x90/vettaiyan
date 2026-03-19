#ifndef TELEMETRY_SHIPPER_H
#define TELEMETRY_SHIPPER_H

/*
 * TelemetryShipper.h -- batched event shipping to a cloud backend.
 *
 * Raw telemetry lives in an in-memory transit buffer (bounded deque).
 * A background thread wakes every FLUSH_INTERVAL_MS and POSTs a batch
 * of NDJSON events to the configured endpoint (Elasticsearch bulk API,
 * Splunk HEC, or any custom collector).
 *
 * If the backend is unreachable, events stay in the buffer until it
 * comes back. If the buffer fills up, oldest events are dropped.
 *
 * Config is in TelemetryShipperConfig -- set before calling Init.
 */

#include <string>
#include <windows.h>
#include "../EdrCommon/EdrEvents.h"

/* Shipping config -- set these before calling InitTelemetryShipper */
struct TelemetryShipperConfig {
    std::string  Endpoint;         /* e.g. "https://elk.corp.com:9200" */
    std::string  IndexOrToken;     /* ES: index name, Splunk: HEC token */
    std::string  AuthHeader;       /* "Authorization: Bearer xxx" or "Splunk xxx" */
    int          BatchSize;        /* Max events per HTTP POST (default 500) */
    int          FlushIntervalMs;  /* How often the shipper wakes (default 2000) */
    int          MaxBufferSize;    /* Max events in transit buffer (default 50000) */

    TelemetryShipperConfig()
        : BatchSize(500)
        , FlushIntervalMs(2000)
        , MaxBufferSize(50000)
    {}
};

/* Lifecycle -- called from Agent.cpp */
bool InitTelemetryShipper(const TelemetryShipperConfig& config);
void ShutdownTelemetryShipper();

/* Push a raw event into the transit buffer.
   Called from OnKernelEvent for all event types.
   Thread-safe, non-blocking, drops oldest if buffer full. */
void ShipEvent(const EDR_EVENT_HEADER* header, const std::wstring& detail);

/* Stats for the dashboard */
struct ShipperStats {
    long long EventsBuffered;
    long long EventsShipped;
    long long EventsDropped;
    long long BatchesSent;
    long long BatchesFailed;
    bool      BackendReachable;
};
ShipperStats GetShipperStats();

#endif
