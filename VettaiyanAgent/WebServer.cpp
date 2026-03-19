#include "WebServer.h"
#include "Log.h"
#include "DbUtil.h"
#include "Utils.h"
#include "Agent.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <httplib.h>
#include <sqlite3.h>
#include <thread>
#include <mutex>
#include <vector>
#include <sstream>
#include <algorithm>

static httplib::Server* g_server = nullptr;
static std::thread g_serverThread;

// SSE clients
static std::mutex g_sseMutex;
struct SseClient {
    httplib::DataSink* sink;
    bool alive;
};
static std::vector<SseClient*> g_sseClients;

extern std::string dbPathUtf8;
extern void EnqueuePath(const std::wstring& path);
extern void EnqueueFilesInDirectory(const std::wstring& dir);

// ─── Helpers ────────────────────────────────────────────

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;
        }
    }
    return out;
}

static std::string ColText(sqlite3_stmt* stmt, int col) {
    const char* t = (const char*)sqlite3_column_text(stmt, col);
    return t ? t : "";
}

static int ColInt(sqlite3_stmt* stmt, int col) {
    return sqlite3_column_int(stmt, col);
}

// ─── DB query helper ────────────────────────────────────

static sqlite3* OpenDb() {
    sqlite3* db = nullptr;
    sqlite3_open(dbPathUtf8.c_str(), &db);
    return db;
}

// ─── API: Dashboard summary ─────────────────────────────

static void ApiDashboard(const httplib::Request&, httplib::Response& res) {
    sqlite3* db = OpenDb();
    if (!db) { res.status = 500; return; }

    int threatCount = 0, eventCount = 0, detectionCount = 0;
    std::string lastScanTime = "N/A", lastScanType = "N/A";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ScanResults", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) threatCount = ColInt(stmt, 0);
        sqlite3_finalize(stmt);
    }
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM TelemetryEvents", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) eventCount = ColInt(stmt, 0);
        sqlite3_finalize(stmt);
    }
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM BehaviorDetections", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) detectionCount = ColInt(stmt, 0);
        sqlite3_finalize(stmt);
    }
    if (sqlite3_prepare_v2(db, "SELECT Timestamp, ScanType FROM ScanStats ORDER BY Id DESC LIMIT 1", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            lastScanTime = ColText(stmt, 0);
            lastScanType = ColText(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }

    // System info
    char hostname[256] = {};
    DWORD hsize = sizeof(hostname);
    GetComputerNameA(hostname, &hsize);

    char username[256] = {};
    DWORD usize = sizeof(username);
    GetUserNameA(username, &usize);

    sqlite3_close(db);

    std::ostringstream json;
    json << "{\"hostname\":\"" << JsonEscape(hostname) << "\","
         << "\"user\":\"" << JsonEscape(username) << "\","
         << "\"threatCount\":" << threatCount << ","
         << "\"eventCount\":" << eventCount << ","
         << "\"detectionCount\":" << detectionCount << ","
         << "\"lastScanTime\":\"" << JsonEscape(lastScanTime) << "\","
         << "\"lastScanType\":\"" << JsonEscape(lastScanType) << "\"}";

    res.set_content(json.str(), "application/json");
}

// ─── API: Threats (ScanResults) ─────────────────────────

static void ApiThreats(const httplib::Request& req, httplib::Response& res) {
    int page = 1, size = 10;
    if (req.has_param("page")) page = std::max(1, std::stoi(req.get_param_value("page")));
    if (req.has_param("size")) size = std::clamp(std::stoi(req.get_param_value("size")), 1, 100);
    int offset = (page - 1) * size;

    sqlite3* db = OpenDb();
    if (!db) { res.status = 500; return; }

    int total = 0;
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ScanResults", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) total = ColInt(stmt, 0);
        sqlite3_finalize(stmt);
    }

    std::ostringstream json;
    json << "{\"total\":" << total << ",\"page\":" << page << ",\"items\":[";

    const char* sql = "SELECT id, ruleName, fileName, filePath, fileHash, fileType, scanType, timestamp, actionTaken, reason "
                      "FROM ScanResults ORDER BY id DESC LIMIT ? OFFSET ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, size);
        sqlite3_bind_int(stmt, 2, offset);
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json << ",";
            first = false;
            json << "{\"id\":" << ColInt(stmt, 0)
                 << ",\"ruleName\":\"" << JsonEscape(ColText(stmt, 1)) << "\""
                 << ",\"fileName\":\"" << JsonEscape(ColText(stmt, 2)) << "\""
                 << ",\"filePath\":\"" << JsonEscape(ColText(stmt, 3)) << "\""
                 << ",\"fileHash\":\"" << JsonEscape(ColText(stmt, 4)) << "\""
                 << ",\"fileType\":\"" << JsonEscape(ColText(stmt, 5)) << "\""
                 << ",\"scanType\":\"" << JsonEscape(ColText(stmt, 6)) << "\""
                 << ",\"timestamp\":\"" << JsonEscape(ColText(stmt, 7)) << "\""
                 << ",\"actionTaken\":\"" << JsonEscape(ColText(stmt, 8)) << "\""
                 << ",\"reason\":\"" << JsonEscape(ColText(stmt, 9)) << "\"}";
        }
        sqlite3_finalize(stmt);
    }
    json << "]}";
    sqlite3_close(db);
    res.set_content(json.str(), "application/json");
}

// ─── API: Events (TelemetryEvents) ─────────────────────

static void ApiEvents(const httplib::Request& req, httplib::Response& res) {
    int page = 1, size = 50;
    std::string type = "all";
    if (req.has_param("page")) page = std::max(1, std::stoi(req.get_param_value("page")));
    if (req.has_param("size")) size = std::clamp(std::stoi(req.get_param_value("size")), 1, 200);
    if (req.has_param("type")) type = req.get_param_value("type");
    int offset = (page - 1) * size;

    sqlite3* db = OpenDb();
    if (!db) { res.status = 500; return; }

    int total = 0;
    sqlite3_stmt* stmt;
    if (type == "all") {
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM TelemetryEvents", -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) total = ColInt(stmt, 0);
            sqlite3_finalize(stmt);
        }
    } else {
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM TelemetryEvents WHERE eventType LIKE ?", -1, &stmt, nullptr) == SQLITE_OK) {
            std::string pattern = type + "%";
            sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) total = ColInt(stmt, 0);
            sqlite3_finalize(stmt);
        }
    }

    std::ostringstream json;
    json << "{\"total\":" << total << ",\"page\":" << page << ",\"items\":[";

    const char* sql = (type == "all")
        ? "SELECT id, eventType, processId, threadId, timestamp, detail, sequenceNumber FROM TelemetryEvents ORDER BY id DESC LIMIT ? OFFSET ?"
        : "SELECT id, eventType, processId, threadId, timestamp, detail, sequenceNumber FROM TelemetryEvents WHERE eventType LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        int paramIdx = 1;
        if (type != "all") {
            std::string pattern = type + "%";
            sqlite3_bind_text(stmt, paramIdx++, pattern.c_str(), -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int(stmt, paramIdx++, size);
        sqlite3_bind_int(stmt, paramIdx, offset);

        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json << ",";
            first = false;
            json << "{\"id\":" << ColInt(stmt, 0)
                 << ",\"eventType\":\"" << JsonEscape(ColText(stmt, 1)) << "\""
                 << ",\"processId\":" << ColInt(stmt, 2)
                 << ",\"threadId\":" << ColInt(stmt, 3)
                 << ",\"timestamp\":\"" << JsonEscape(ColText(stmt, 4)) << "\""
                 << ",\"detail\":\"" << JsonEscape(ColText(stmt, 5)) << "\""
                 << ",\"sequenceNumber\":" << ColInt(stmt, 6) << "}";
        }
        sqlite3_finalize(stmt);
    }
    json << "]}";
    sqlite3_close(db);
    res.set_content(json.str(), "application/json");
}

// ─── API: BehaviorDetections ────────────────────────────

static void ApiDetections(const httplib::Request& req, httplib::Response& res) {
    int page = 1, size = 20;
    if (req.has_param("page")) page = std::max(1, std::stoi(req.get_param_value("page")));
    if (req.has_param("size")) size = std::clamp(std::stoi(req.get_param_value("size")), 1, 100);
    int offset = (page - 1) * size;

    sqlite3* db = OpenDb();
    if (!db) { res.status = 500; return; }

    int total = 0;
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM BehaviorDetections", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) total = ColInt(stmt, 0);
        sqlite3_finalize(stmt);
    }

    std::ostringstream json;
    json << "{\"total\":" << total << ",\"page\":" << page << ",\"items\":[";

    const char* sql = "SELECT id, ruleName, description, mitreTactic, mitreTechnique, severity, "
                      "processId, parentProcessId, processImage, parentImage, timestamp "
                      "FROM BehaviorDetections ORDER BY id DESC LIMIT ? OFFSET ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, size);
        sqlite3_bind_int(stmt, 2, offset);
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json << ",";
            first = false;
            json << "{\"id\":" << ColInt(stmt, 0)
                 << ",\"ruleName\":\"" << JsonEscape(ColText(stmt, 1)) << "\""
                 << ",\"description\":\"" << JsonEscape(ColText(stmt, 2)) << "\""
                 << ",\"mitreTactic\":\"" << JsonEscape(ColText(stmt, 3)) << "\""
                 << ",\"mitreTechnique\":\"" << JsonEscape(ColText(stmt, 4)) << "\""
                 << ",\"severity\":" << ColInt(stmt, 5)
                 << ",\"processId\":" << ColInt(stmt, 6)
                 << ",\"parentProcessId\":" << ColInt(stmt, 7)
                 << ",\"processImage\":\"" << JsonEscape(ColText(stmt, 8)) << "\""
                 << ",\"parentImage\":\"" << JsonEscape(ColText(stmt, 9)) << "\""
                 << ",\"timestamp\":\"" << JsonEscape(ColText(stmt, 10)) << "\"}";
        }
        sqlite3_finalize(stmt);
    }
    json << "]}";
    sqlite3_close(db);
    res.set_content(json.str(), "application/json");
}

// ─── API: Scan Stats ────────────────────────────────────

static void ApiScanStats(const httplib::Request&, httplib::Response& res) {
    sqlite3* db = OpenDb();
    if (!db) { res.status = 500; return; }

    sqlite3_stmt* stmt;
    std::ostringstream json;
    json << "{";
    if (sqlite3_prepare_v2(db, "SELECT Timestamp, ScanType, ScanDuration, ThreatsFound, FilesScanned FROM ScanStats ORDER BY Id DESC LIMIT 1", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            json << "\"timestamp\":\"" << JsonEscape(ColText(stmt, 0)) << "\""
                 << ",\"scanType\":\"" << JsonEscape(ColText(stmt, 1)) << "\""
                 << ",\"duration\":\"" << JsonEscape(ColText(stmt, 2)) << "\""
                 << ",\"threatsFound\":\"" << JsonEscape(ColText(stmt, 3)) << "\""
                 << ",\"filesScanned\":\"" << JsonEscape(ColText(stmt, 4)) << "\"";
        } else {
            json << "\"timestamp\":\"N/A\",\"scanType\":\"N/A\",\"duration\":\"N/A\",\"threatsFound\":\"0\",\"filesScanned\":\"0\"";
        }
        sqlite3_finalize(stmt);
    }
    json << "}";
    sqlite3_close(db);
    res.set_content(json.str(), "application/json");
}

// ─── API: Trigger Scan ──────────────────────────────────

static void ApiScanTrigger(const httplib::Request& req, httplib::Response& res) {
    // Expect body like: path=C:\Users\...
    std::string path;
    if (req.has_param("path")) {
        path = req.get_param_value("path");
    } else if (req.body.find("path=") != std::string::npos) {
        path = req.body.substr(req.body.find("path=") + 5);
    }

    if (path.empty()) {
        res.set_content("{\"error\":\"No path specified\"}", "application/json");
        res.status = 400;
        return;
    }

    std::wstring wpath(path.begin(), path.end());
    EnqueueFilesInDirectory(wpath);
    res.set_content("{\"status\":\"queued\",\"path\":\"" + JsonEscape(path) + "\"}", "application/json");
}

// ─── API: Response Actions (via Command pipe) ───────────

static std::string SendCommandToSelf(const std::string& cmd) {
    // Instead of going through pipe, we call the command handler directly
    // For now, use the pipe approach since the command thread handles it
    HANDLE hPipe = CreateFileW(COMMAND_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) return "ERROR|Cannot connect to command pipe";

    std::wstring wcmd(cmd.begin(), cmd.end());
    DWORD written, bytesRead;
    WriteFile(hPipe, wcmd.c_str(), (DWORD)(wcmd.size() * sizeof(wchar_t)), &written, nullptr);

    wchar_t buffer[2048] = {};
    ReadFile(hPipe, buffer, sizeof(buffer) - 2, &bytesRead, nullptr);
    CloseHandle(hPipe);

    std::wstring wresult(buffer, bytesRead / sizeof(wchar_t));
    return std::string(wresult.begin(), wresult.end());
}

static void ApiResponseAction(const httplib::Request& req, httplib::Response& res) {
    std::string action = req.matches[1];
    std::string result;

    if (action == "kill") {
        std::string pid;
        if (req.has_param("pid")) pid = req.get_param_value("pid");
        else if (!req.body.empty()) pid = req.body;
        result = SendCommandToSelf("KILL|" + pid);
    } else if (action == "quarantine") {
        std::string path;
        if (req.has_param("path")) path = req.get_param_value("path");
        else if (!req.body.empty()) path = req.body;
        result = SendCommandToSelf("QUARANTINE|" + path);
    } else if (action == "isolate") {
        result = SendCommandToSelf("ISOLATE");
    } else if (action == "unisolate") {
        result = SendCommandToSelf("UNISOLATE");
    } else if (action == "status") {
        result = SendCommandToSelf("STATUS");
    } else {
        res.set_content("{\"error\":\"Unknown action\"}", "application/json");
        res.status = 400;
        return;
    }

    res.set_content("{\"result\":\"" + JsonEscape(result) + "\"}", "application/json");
}

// ─── SSE: Notifications ─────────────────────────────────

static void ApiNotifications(const httplib::Request&, httplib::Response& res) {
    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");

    res.set_chunked_content_provider("text/event-stream",
        [](size_t, httplib::DataSink& sink) {
            auto client = new SseClient{ &sink, true };
            {
                std::lock_guard<std::mutex> lock(g_sseMutex);
                g_sseClients.push_back(client);
            }

            // Send initial keepalive
            sink.write(": connected\n\n", 14);

            // Block until client disconnects
            while (client->alive) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if (!sink.is_writable()) {
                    client->alive = false;
                }
            }

            {
                std::lock_guard<std::mutex> lock(g_sseMutex);
                g_sseClients.erase(
                    std::remove(g_sseClients.begin(), g_sseClients.end(), client),
                    g_sseClients.end());
            }
            delete client;
            return false;
        }
    );
}

// ─── Broadcast to all SSE clients ───────────────────────

void BroadcastNotification(const std::string& type, const std::string& title, const std::string& message) {
    std::string event = "data: {\"type\":\"" + JsonEscape(type)
        + "\",\"title\":\"" + JsonEscape(title)
        + "\",\"message\":\"" + JsonEscape(message) + "\"}\n\n";

    std::lock_guard<std::mutex> lock(g_sseMutex);
    for (auto* client : g_sseClients) {
        if (client->alive && client->sink->is_writable()) {
            client->sink->write(event.c_str(), event.size());
        }
    }
}

// ─── Server lifecycle ───────────────────────────────────

void StartWebServer() {
    g_server = new httplib::Server();

    // Determine web root directory
    std::wstring webDir = GetAssetPath(L"web");
    std::string webDirUtf8(webDir.begin(), webDir.end());

    // API routes
    g_server->Get("/api/dashboard", ApiDashboard);
    g_server->Get("/api/threats", ApiThreats);
    g_server->Get("/api/events", ApiEvents);
    g_server->Get("/api/detections", ApiDetections);
    g_server->Get("/api/scan/stats", ApiScanStats);
    g_server->Post("/api/scan", ApiScanTrigger);
    g_server->Post(R"(/api/response/(\w+))", ApiResponseAction);
    g_server->Get("/api/notifications", ApiNotifications);

    // Serve static files from web/ directory
    g_server->set_mount_point("/", webDirUtf8);

    g_serverThread = std::thread([] {
        LogMessage(L"[ WebServer ] Starting on http://127.0.0.1:" + std::to_wstring(EDR_WEB_PORT));
        g_server->listen(EDR_WEB_HOST, EDR_WEB_PORT);
    });
    g_serverThread.detach();
}

void StopWebServer() {
    if (g_server) {
        g_server->stop();
        delete g_server;
        g_server = nullptr;
    }
    // Kill SSE clients
    std::lock_guard<std::mutex> lock(g_sseMutex);
    for (auto* c : g_sseClients) c->alive = false;
    g_sseClients.clear();
}
