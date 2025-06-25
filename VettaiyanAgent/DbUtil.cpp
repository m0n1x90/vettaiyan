#include "Log.h"
#include "DbUtil.h"
#include "YaraScanner.h"

std::wstring scanDbPath = GetAssetPath(L"data.db");

std::string dbPathUtf8(scanDbPath.begin(), scanDbPath.end());

void SaveScanResultToDB(const YaraScanResult& result) {

    sqlite3* db;
    if (sqlite3_open(dbPathUtf8.c_str(), &db) != SQLITE_OK) {
        LogMessage(L"[DB] Failed to open database: " + Utf8ToWide(sqlite3_errmsg(db)));
        return;
    }

    std::string ruleName = std::string(result.ruleName.begin(), result.ruleName.end());
    std::string fileName = std::string(result.fileName.begin(), result.fileName.end());
    std::string filePath = std::string(result.filePath.begin(), result.filePath.end());
    std::string fileHash = std::string(result.fileHash.begin(), result.fileHash.end());
    std::string fileType = std::string(result.fileType.begin(), result.fileType.end());
    std::string scanType = std::string(result.scanType.begin(), result.scanType.end());
    std::string actionTaken = std::string(result.actionTaken.begin(), result.actionTaken.end());
    std::string reason = std::string(result.reason.begin(), result.reason.end());

    std::string query =
        "INSERT INTO ScanResults (ruleName, fileName, filePath, fileHash, fileType, scanType, actionTaken, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LogMessage(L"[DB] Failed to prepare insert statement: " + Utf8ToWide(sqlite3_errmsg(db)));
        sqlite3_close(db);
        return;
    }

    sqlite3_bind_text(stmt, 1, ruleName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, fileName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, filePath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, fileHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, fileType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, scanType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, actionTaken.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, reason.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LogMessage(L"[DB] Insert failed: " + Utf8ToWide(sqlite3_errmsg(db)));
    }
    else {
        LogMessage(L"[DB] Insert successful.");
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

}
