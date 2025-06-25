#ifndef SUPPORT_H
#define SUPPORT_H

#include <string>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#define YARA_REGISTRY_CONTEXT L"Software\\Classes\\*\\shell\\ScanWithVettaiyan";

#define ASSET_ICON_PATH L"Assets\\icons\\VettaiyanLogo.ico";

void AddContextMenuEntry();

void RemoveContextMenuEntry();

#endif