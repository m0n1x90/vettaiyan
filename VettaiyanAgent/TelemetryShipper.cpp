/*
 * TelemetryShipper.cpp -- batched event shipping to a cloud backend.
 *
 * Architecture:
 *   ShipEvent() → transit buffer (bounded deque, mutex-protected)
 *   Shipper thread → wakes every FlushIntervalMs
 *     → drains up to BatchSize events from buffer
 *     → serializes as NDJSON (one JSON object per line)
 *     → HTTP POST to configured endpoint
 *     → on success: events are gone
 *     → on failure: events stay in a retry batch for next cycle
 *
 * NDJSON format is compatible with:
 *   - Elasticsearch _bulk API
 *   - Splunk HEC (raw endpoint)
 *   - Any custom HTTP collector
 *
 * The transit buffer is bounded by MaxBufferSize. When full, oldest
 * events are dropped (front of deque). This ensures the agent never
 * runs out of memory even if the backend is down for hours.
 */

#include "TelemetryShipper.h"
#include "Log.h"

#include <httplib.h>
#include <windows.h>

#include <thread>
#include <mutex>
#include <deque>
#include <string>
#include <sstream>
#include <atomic>

/* ---- Helpers ---- */

static std::string WideToUtf8(const std::wstring& wide)
{
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &out[0], len, nullptr, nullptr);
    return out;
}

static const char* EventTypeToString(EDR_EVENT_TYPE type)
{
    switch (type) {
    case EdrEventProcessCreate:       return "ProcessCreate";
    case EdrEventProcessTerminate:    return "ProcessTerminate";
    case EdrEventImageLoad:           return "ImageLoad";
    case EdrEventThreadCreate:        return "ThreadCreate";
    case EdrEventThreadTerminate:     return "ThreadTerminate";
    case EdrEventRegistrySetValue:    return "RegistrySetValue";
    case EdrEventRegistryDeleteValue: return "RegistryDeleteValue";
    case EdrEventRegistryDeleteKey:   return "RegistryDeleteKey";
    case EdrEventRegistryRenameKey:   return "RegistryRenameKey";
    case EdrEventRegistryCreateKey:   return "RegistryCreateKey";
    case EdrEventFileCreate:          return "FileCreate";
    case EdrEventFileWrite:           return "FileWrite";
    case EdrEventFileDelete:          return "FileDelete";
    case EdrEventFileRename:          return "FileRename";
    case EdrEventFileClose:           return "FileClose";
    case EdrEventHandleCreate:        return "HandleCreate";
    case EdrEventHandleDuplicate:     return "HandleDuplicate";
    default:                          return "Unknown";
    }
}

/* Escape a UTF-8 string for JSON -- handles \, ", and control chars */
static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

/* ---- Transit buffer ---- */

struct TelemetryEvent {
    std::string json;   /* Pre-serialized JSON line (no trailing newline) */
};

static TelemetryShipperConfig g_Config;
static std::mutex             g_BufferMutex;
static std::deque<TelemetryEvent> g_Buffer;

static std::thread            g_ShipperThread;
static std::atomic<bool>      g_Running{false};
static HANDLE                 g_FlushEvent = NULL;  /* Signaled to wake shipper early */

/* ---- Stats ---- */
static std::atomic<long long> g_EventsBuffered{0};
static std::atomic<long long> g_EventsShipped{0};
static std::atomic<long long> g_EventsDropped{0};
static std::atomic<long long> g_BatchesSent{0};
static std::atomic<long long> g_BatchesFailed{0};
static std::atomic<bool>      g_BackendReachable{false};

/* ---- Hostname (cached once at init) ---- */
static std::string g_Hostname;

static std::string GetHostname()
{
    char buf[256] = {};
    DWORD size = sizeof(buf);
    if (GetComputerNameExA(ComputerNameDnsHostname, buf, &size)) {
        return buf;
    }
    return "unknown";
}

/* ---- JSON serialization ---- */

static std::string SerializeEvent(const EDR_EVENT_HEADER* header, const std::string& detailUtf8)
{
    /* Convert LARGE_INTEGER timestamp to ISO 8601.
       Kernel timestamp is 100ns intervals since 1601-01-01.
       We convert to SYSTEMTIME then format. */
    SYSTEMTIME st = {};
    FILETIME ft;
    ft.dwLowDateTime  = header->Timestamp.LowPart;
    ft.dwHighDateTime = (DWORD)header->Timestamp.HighPart;
    FileTimeToSystemTime(&ft, &st);

    char timeBuf[32];
    snprintf(timeBuf, sizeof(timeBuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    /* Build JSON manually -- avoids pulling in a JSON library.
       Simple and fast for a fixed schema. */
    std::ostringstream js;
    js << "{"
       << "\"host\":\"" << JsonEscape(g_Hostname) << "\","
       << "\"eventType\":\"" << EventTypeToString(header->EventType) << "\","
       << "\"processId\":" << header->ProcessId << ","
       << "\"threadId\":" << header->ThreadId << ","
       << "\"sequenceNumber\":" << header->SequenceNumber << ","
       << "\"timestamp\":\"" << timeBuf << "\","
       << "\"detail\":\"" << JsonEscape(detailUtf8) << "\""
       << "}";
    return js.str();
}

/* ---- Shipper thread ---- */

static void ShipperLoop()
{
    /* Parse endpoint URL into host + path */
    std::string host = g_Config.Endpoint;
    std::string path = "/";

    /* Extract path from URL if present (e.g. "https://host:9200/_bulk") */
    size_t schemeEnd = host.find("://");
    if (schemeEnd != std::string::npos) {
        size_t pathStart = host.find('/', schemeEnd + 3);
        if (pathStart != std::string::npos) {
            path = host.substr(pathStart);
            host = host.substr(0, pathStart);
        }
    }

    /* Detect Elasticsearch _bulk API -- needs action metadata lines.
       Build the action line once: {"index":{"_index":"<index>"}} */
    bool isElasticBulk = (path.find("_bulk") != std::string::npos);
    std::string bulkActionLine;
    if (isElasticBulk) {
        std::string indexName = g_Config.IndexOrToken.empty() ? "vettaiyan-events" : g_Config.IndexOrToken;
        bulkActionLine = "{\"index\":{\"_index\":\"" + indexName + "\"}}\n";
        /* Strip index prefix from path if user included it (e.g. /vettaiyan-events/_bulk -> /_bulk) */
        if (path != "/_bulk") path = "/_bulk";
    }

    /* Create HTTP client -- cpp-httplib auto-detects HTTPS from scheme */
    httplib::Client client(host);
    client.set_connection_timeout(5);
    client.set_read_timeout(10);
    client.set_write_timeout(10);

    while (g_Running.load()) {
        /* Sleep until flush interval or early wake */
        WaitForSingleObject(g_FlushEvent, (DWORD)g_Config.FlushIntervalMs);

        if (!g_Running.load()) break;

        /* Drain up to BatchSize events from the buffer */
        std::vector<std::string> batch;
        {
            std::lock_guard<std::mutex> lock(g_BufferMutex);
            int count = (int)g_Buffer.size() < g_Config.BatchSize ? (int)g_Buffer.size() : g_Config.BatchSize;
            batch.reserve(count);
            for (int i = 0; i < count; i++) {
                batch.push_back(std::move(g_Buffer.front().json));
                g_Buffer.pop_front();
            }
        }

        if (batch.empty()) continue;

        /* Build NDJSON body. For Elasticsearch _bulk API, each document
           needs an action metadata line before it:
             {"index":{"_index":"vettaiyan-events"}}
             {"host":"pc1","eventType":"ProcessCreate",...}
           For other backends, just one JSON object per line. */
        std::string body;
        size_t estimatedSize = 0;
        for (auto& line : batch) estimatedSize += line.size() + bulkActionLine.size() + 2;
        body.reserve(estimatedSize);
        for (auto& line : batch) {
            if (isElasticBulk) body += bulkActionLine;
            body += line;
            body += '\n';
        }

        /* POST to backend -- use application/x-ndjson for ES compatibility */
        httplib::Headers headers;
        if (!g_Config.AuthHeader.empty()) {
            /* Parse "HeaderName: Value" format */
            size_t colonPos = g_Config.AuthHeader.find(':');
            if (colonPos != std::string::npos) {
                std::string key = g_Config.AuthHeader.substr(0, colonPos);
                std::string val = g_Config.AuthHeader.substr(colonPos + 1);
                /* Trim leading whitespace from value */
                size_t valStart = val.find_first_not_of(' ');
                if (valStart != std::string::npos) val = val.substr(valStart);
                headers.emplace(key, val);
            }
        }

        auto res = client.Post(path, headers, body, "application/x-ndjson");

        if (res && res->status >= 200 && res->status < 300) {
            g_EventsShipped.fetch_add((long long)batch.size());
            g_BatchesSent.fetch_add(1);
            g_BackendReachable.store(true);
        } else {
            /* Ship failed -- put events back at the front of the buffer
               so they'll be retried next cycle */
            {
                std::lock_guard<std::mutex> lock(g_BufferMutex);
                for (int i = (int)batch.size() - 1; i >= 0; i--) {
                    g_Buffer.push_front(TelemetryEvent{ std::move(batch[i]) });
                }
                /* If re-insert caused overflow, drop from the back (newest) */
                while ((int)g_Buffer.size() > g_Config.MaxBufferSize) {
                    g_Buffer.pop_back();
                    g_EventsDropped.fetch_add(1);
                }
            }
            g_BatchesFailed.fetch_add(1);
            g_BackendReachable.store(false);

            int statusCode = res ? res->status : 0;
            LogMessage(L"TelemetryShipper: POST failed (status=" + std::to_wstring(statusCode) +
                L"), " + std::to_wstring(batch.size()) + L" events re-queued");
        }
    }
}

/* ---- Public API ---- */

bool InitTelemetryShipper(const TelemetryShipperConfig& config)
{
    if (config.Endpoint.empty()) {
        LogMessage(L"TelemetryShipper: No endpoint configured, shipping disabled");
        return false;
    }

    g_Config = config;
    g_Hostname = GetHostname();

    g_FlushEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_FlushEvent) return false;

    g_Running.store(true);
    g_ShipperThread = std::thread(ShipperLoop);

    LogMessage(L"TelemetryShipper: Initialized (endpoint=" +
        std::wstring(config.Endpoint.begin(), config.Endpoint.end()) +
        L", batch=" + std::to_wstring(config.BatchSize) +
        L", flush=" + std::to_wstring(config.FlushIntervalMs) + L"ms" +
        L", buffer=" + std::to_wstring(config.MaxBufferSize) + L")");
    return true;
}


void ShutdownTelemetryShipper()
{
    g_Running.store(false);

    if (g_FlushEvent) {
        SetEvent(g_FlushEvent);  /* Wake the shipper so it exits */
    }

    if (g_ShipperThread.joinable()) {
        g_ShipperThread.join();
    }

    if (g_FlushEvent) {
        CloseHandle(g_FlushEvent);
        g_FlushEvent = NULL;
    }

    /* Log final stats */
    LogMessage(L"TelemetryShipper: Shutdown. Shipped=" + std::to_wstring(g_EventsShipped.load()) +
        L" Dropped=" + std::to_wstring(g_EventsDropped.load()) +
        L" Buffered=" + std::to_wstring(g_Buffer.size()));

    g_Buffer.clear();
}


void ShipEvent(const EDR_EVENT_HEADER* header, const std::wstring& detail)
{
    if (!g_Running.load() || !header) return;

    std::string detailUtf8 = WideToUtf8(detail);
    std::string json = SerializeEvent(header, detailUtf8);

    std::lock_guard<std::mutex> lock(g_BufferMutex);

    /* If buffer is full, drop the oldest event to make room */
    if ((int)g_Buffer.size() >= g_Config.MaxBufferSize) {
        g_Buffer.pop_front();
        g_EventsDropped.fetch_add(1);
    }

    g_Buffer.push_back(TelemetryEvent{ std::move(json) });
    g_EventsBuffered.fetch_add(1);

    /* Wake shipper early if we've hit batch size */
    if ((int)g_Buffer.size() >= g_Config.BatchSize && g_FlushEvent) {
        SetEvent(g_FlushEvent);
    }
}


ShipperStats GetShipperStats()
{
    ShipperStats stats = {};
    {
        std::lock_guard<std::mutex> lock(g_BufferMutex);
        stats.EventsBuffered = (long long)g_Buffer.size();
    }
    stats.EventsShipped    = g_EventsShipped.load();
    stats.EventsDropped    = g_EventsDropped.load();
    stats.BatchesSent      = g_BatchesSent.load();
    stats.BatchesFailed    = g_BatchesFailed.load();
    stats.BackendReachable = g_BackendReachable.load();
    return stats;
}
