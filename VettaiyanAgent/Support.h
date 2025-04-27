#ifndef SUPPORT_H
#define SUPPORT_H

#include <string>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define LOG_FILE L"\\VettaiyanLogFile.log"

#define YARA_REGISTRY_CONTEXT L"Software\\Classes\\*\\shell\\ScanWithVettaiyan";
#define ASSET_ICON_PATH L"Assets\\icons\\VettaiyanLogo.ico";

void AddContextMenuEntry();
void RemoveContextMenuEntry();
void LogMessage(const std::wstring& message);

#endif