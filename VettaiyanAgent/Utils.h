#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>

#include <magic.h>
#include <sqlite3.h>

std::wstring GetAssetPath(const std::wstring& assetName);

std::wstring GetExecutableDir();

std::wstring Utf8ToWide(const char* utf8Str);

void LoadPathIntoBuffer(std::wstring assetName, wchar_t* buffer, size_t bufferSize);

std::wstring UrlEncode(const std::wstring& value);

std::wstring ComputeSHA256(const std::wstring& filePath);

std::wstring GetMimeType(const std::wstring& filePath);

#endif