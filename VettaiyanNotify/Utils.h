#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <iostream>
#include <windows.h>

std::wstring GetExecutableDir();

std::wstring GetAssetPath(const std::wstring& assetName);

#endif