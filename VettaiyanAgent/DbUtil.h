#ifndef DB_UTILS_H
#define DB_UTILS_H

#include "Utils.h"
#include "YaraScanner.h"

extern std::wstring scanDbPath;

void SaveScanResultToDB(const YaraScanResult& result);

#endif