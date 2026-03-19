/*
 * TelemetryDb.cpp - Telemetry event storage in SQLite
 */

#include "TelemetryDb.h"
#include "Log.h"
#include "Utils.h"

#include <sqlite3.h>
#include <mutex>

static sqlite3* g_TelemetryDb = nullptr;
static std::mutex g_TelemetryMutex;

/* Prepared statements for performance */
static sqlite3_stmt* g_InsertEventStmt = nullptr;
static sqlite3_stmt* g_InsertDetectionStmt = nullptr;
static sqlite3_stmt* g_InsertEtwStmt = nullptr;


static std::string WideToUtf8(const std::wstring& wide)
{
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &result[0], size, NULL, NULL);
    return result;
}


bool InitializeTelemetryDb()
{
    std::lock_guard<std::mutex> lock(g_TelemetryMutex);

    std::wstring dbPathW = GetAssetPath(L"data.db");
    std::string dbPath = WideToUtf8(dbPathW);

    int rc = sqlite3_open(dbPath.c_str(), &g_TelemetryDb);
    if (rc != SQLITE_OK) {
        LogMessage(L"[ TelemetryDb ] Failed to open database");
        return false;
    }

    /* Enable WAL mode for concurrent readers */
    sqlite3_exec(g_TelemetryDb, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_TelemetryDb, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* Create telemetry events table */
    const char* createEvents =
        "CREATE TABLE IF NOT EXISTS TelemetryEvents ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  eventType TEXT NOT NULL,"
        "  processId INTEGER,"
        "  threadId INTEGER,"
        "  timestamp TEXT DEFAULT (CURRENT_TIMESTAMP),"
        "  detail TEXT,"
        "  sequenceNumber INTEGER"
        ");";

    /* Create behavioral detections table */
    const char* createDetections =
        "CREATE TABLE IF NOT EXISTS BehaviorDetections ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ruleName TEXT NOT NULL,"
        "  description TEXT,"
        "  mitreTactic TEXT,"
        "  mitreTechnique TEXT,"
        "  severity INTEGER,"
        "  processId INTEGER,"
        "  parentProcessId INTEGER,"
        "  processImage TEXT,"
        "  parentImage TEXT,"
        "  timestamp TEXT DEFAULT (CURRENT_TIMESTAMP)"
        ");";

    /* Create ETW events table */
    const char* createEtw =
        "CREATE TABLE IF NOT EXISTS EtwEvents ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  eventType TEXT NOT NULL,"
        "  processId INTEGER,"
        "  timestamp TEXT DEFAULT (CURRENT_TIMESTAMP),"
        "  detail TEXT"
        ");";

    /* Create scan results table (previously created by dashboard) */
    const char* createScanResults =
        "CREATE TABLE IF NOT EXISTS ScanResults ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ruleName TEXT, fileName TEXT, filePath TEXT,"
        "  fileHash TEXT, fileType TEXT, scanType TEXT,"
        "  timestamp TEXT DEFAULT (CURRENT_TIMESTAMP),"
        "  actionTaken TEXT, reason TEXT"
        ");";

    /* Create scan stats table */
    const char* createScanStats =
        "CREATE TABLE IF NOT EXISTS ScanStats ("
        "  Id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ScanType TEXT, Timestamp TEXT DEFAULT (CURRENT_TIMESTAMP),"
        "  ScanDuration TEXT, ThreatsFound INTEGER DEFAULT 0,"
        "  FilesScanned INTEGER DEFAULT 0"
        ");";

    /* Create indices for common queries */
    const char* createIndices =
        "CREATE INDEX IF NOT EXISTS idx_telemetry_type ON TelemetryEvents(eventType);"
        "CREATE INDEX IF NOT EXISTS idx_telemetry_pid ON TelemetryEvents(processId);"
        "CREATE INDEX IF NOT EXISTS idx_telemetry_time ON TelemetryEvents(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_detection_severity ON BehaviorDetections(severity);"
        "CREATE INDEX IF NOT EXISTS idx_detection_time ON BehaviorDetections(timestamp);"
        "CREATE INDEX IF NOT EXISTS idx_etw_type ON EtwEvents(eventType);"
        "CREATE INDEX IF NOT EXISTS idx_etw_time ON EtwEvents(timestamp);";

    char* errMsg = nullptr;
    sqlite3_exec(g_TelemetryDb, createEvents, NULL, NULL, &errMsg);
    if (errMsg) { sqlite3_free(errMsg); errMsg = nullptr; }

    sqlite3_exec(g_TelemetryDb, createDetections, NULL, NULL, &errMsg);
    if (errMsg) { sqlite3_free(errMsg); errMsg = nullptr; }

    sqlite3_exec(g_TelemetryDb, createEtw, NULL, NULL, &errMsg);
    if (errMsg) { sqlite3_free(errMsg); errMsg = nullptr; }

    sqlite3_exec(g_TelemetryDb, createScanResults, NULL, NULL, &errMsg);
    if (errMsg) { sqlite3_free(errMsg); errMsg = nullptr; }

    sqlite3_exec(g_TelemetryDb, createScanStats, NULL, NULL, &errMsg);
    if (errMsg) { sqlite3_free(errMsg); errMsg = nullptr; }

    sqlite3_exec(g_TelemetryDb, createIndices, NULL, NULL, &errMsg);
    if (errMsg) { sqlite3_free(errMsg); errMsg = nullptr; }

    /* Prepare insert statements */
    sqlite3_prepare_v2(g_TelemetryDb,
        "INSERT INTO TelemetryEvents (eventType, processId, threadId, detail, sequenceNumber) VALUES (?, ?, ?, ?, ?);",
        -1, &g_InsertEventStmt, NULL);

    sqlite3_prepare_v2(g_TelemetryDb,
        "INSERT INTO BehaviorDetections (ruleName, description, mitreTactic, mitreTechnique, severity, processId, parentProcessId, processImage, parentImage) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        -1, &g_InsertDetectionStmt, NULL);

    sqlite3_prepare_v2(g_TelemetryDb,
        "INSERT INTO EtwEvents (eventType, processId, detail) VALUES (?, ?, ?);",
        -1, &g_InsertEtwStmt, NULL);

    LogMessage(L"[ TelemetryDb ] Database initialized with WAL mode");
    return true;
}


void ShutdownTelemetryDb()
{
    std::lock_guard<std::mutex> lock(g_TelemetryMutex);

    if (g_InsertEventStmt) { sqlite3_finalize(g_InsertEventStmt); g_InsertEventStmt = nullptr; }
    if (g_InsertDetectionStmt) { sqlite3_finalize(g_InsertDetectionStmt); g_InsertDetectionStmt = nullptr; }
    if (g_InsertEtwStmt) { sqlite3_finalize(g_InsertEtwStmt); g_InsertEtwStmt = nullptr; }

    if (g_TelemetryDb) {
        sqlite3_close(g_TelemetryDb);
        g_TelemetryDb = nullptr;
    }

    LogMessage(L"[ TelemetryDb ] Shutdown");
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


void StoreKernelEvent(const EDR_EVENT_HEADER* header, const std::wstring& detail)
{
    if (!header) return;

    std::lock_guard<std::mutex> lock(g_TelemetryMutex);
    if (!g_InsertEventStmt || !g_TelemetryDb) return;

    sqlite3_reset(g_InsertEventStmt);
    sqlite3_bind_text(g_InsertEventStmt, 1, EventTypeToString(header->EventType), -1, SQLITE_STATIC);
    sqlite3_bind_int(g_InsertEventStmt, 2, header->ProcessId);
    sqlite3_bind_int(g_InsertEventStmt, 3, header->ThreadId);

    std::string detailUtf8 = WideToUtf8(detail);
    sqlite3_bind_text(g_InsertEventStmt, 4, detailUtf8.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_InsertEventStmt, 5, header->SequenceNumber);

    sqlite3_step(g_InsertEventStmt);
}


void StoreBehaviorDetection(const BehaviorDetection& detection)
{
    std::lock_guard<std::mutex> lock(g_TelemetryMutex);
    if (!g_InsertDetectionStmt || !g_TelemetryDb) return;

    sqlite3_reset(g_InsertDetectionStmt);
    sqlite3_bind_text(g_InsertDetectionStmt, 1, WideToUtf8(detection.RuleName).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_InsertDetectionStmt, 2, WideToUtf8(detection.Description).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_InsertDetectionStmt, 3, WideToUtf8(detection.MitreTactic).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_InsertDetectionStmt, 4, WideToUtf8(detection.MitreTechnique).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_InsertDetectionStmt, 5, (int)detection.Severity);
    sqlite3_bind_int(g_InsertDetectionStmt, 6, detection.ProcessId);
    sqlite3_bind_int(g_InsertDetectionStmt, 7, detection.ParentProcessId);
    sqlite3_bind_text(g_InsertDetectionStmt, 8, WideToUtf8(detection.ProcessImage).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_InsertDetectionStmt, 9, WideToUtf8(detection.ParentImage).c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(g_InsertDetectionStmt);
}


void StoreEtwEvent(const std::wstring& type, ULONG pid, const std::wstring& detail)
{
    std::lock_guard<std::mutex> lock(g_TelemetryMutex);
    if (!g_InsertEtwStmt || !g_TelemetryDb) return;

    sqlite3_reset(g_InsertEtwStmt);
    sqlite3_bind_text(g_InsertEtwStmt, 1, WideToUtf8(type).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_InsertEtwStmt, 2, pid);
    sqlite3_bind_text(g_InsertEtwStmt, 3, WideToUtf8(detail).c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(g_InsertEtwStmt);
}


int GetTelemetryEventCount()
{
    std::lock_guard<std::mutex> lock(g_TelemetryMutex);
    if (!g_TelemetryDb) return 0;

    sqlite3_stmt* stmt;
    int count = 0;
    if (sqlite3_prepare_v2(g_TelemetryDb, "SELECT COUNT(*) FROM TelemetryEvents;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return count;
}


int GetBehaviorDetectionCount()
{
    std::lock_guard<std::mutex> lock(g_TelemetryMutex);
    if (!g_TelemetryDb) return 0;

    sqlite3_stmt* stmt;
    int count = 0;
    if (sqlite3_prepare_v2(g_TelemetryDb, "SELECT COUNT(*) FROM BehaviorDetections;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return count;
}
