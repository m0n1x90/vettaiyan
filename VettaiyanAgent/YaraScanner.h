#ifndef YARA_SCANNER_H
#define YARA_SCANNER_H

#include <string>
#include <vector>
#include <yara.h>
#include <shlwapi.h>

#pragma comment(lib, "libyara.lib")
#pragma comment(lib, "Shlwapi.lib")

const std::wstring YARA_RULES_PATH = L"Assets\\rules\\vettaiyan.rules";

struct YaraScanResult {
    bool matched;
    std::wstring reason;
    std::wstring filePath;
};

int YaraScanCallback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
);

bool InitializeYara();

void FinalizeYara();

YaraScanResult ScanFileWithYara(const std::wstring& filePath);

#endif