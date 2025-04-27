#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <iostream>
#include <windows.h>

const std::wstring SCANNER_EXECUTABLE = L"VettaiyanScanner.exe";

std::wstring GetExecutableDir();

std::wstring GetAssetPath(const std::wstring& assetName);

void LoadPathIntoBuffer(std::wstring assetName, wchar_t* buffer, size_t bufferSize);

#endif