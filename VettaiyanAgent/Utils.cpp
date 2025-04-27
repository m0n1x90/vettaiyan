#include "Utils.h"

std::wstring GetExecutableDir() {
    wchar_t path[MAX_PATH];
    DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (length == 0 || length == MAX_PATH) {
        std::wcerr << L"[-] GetModuleFileNameW() error" << std::endl;
        return L"";
    }

    // Strip the filename from the path
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? fullPath.substr(0, pos) : L"";
}

std::wstring GetAssetPath(const std::wstring& assetName) {
    std::wstring cwd = GetExecutableDir();
    return cwd + L"\\" + assetName;
}

void LoadPathIntoBuffer(std::wstring assetName, wchar_t* buffer, size_t bufferSize) {
    std::wstring scannerPath = GetAssetPath(assetName);

    if (!scannerPath.empty()) {
        if (scannerPath.length() < bufferSize) {
            wcscpy_s(buffer, bufferSize, scannerPath.c_str());
            std::wcout << L"Scanner path loaded: " << buffer << std::endl;
        }
        else {
            std::wcerr << L"Buffer too small to hold scanner path!" << std::endl;
        }
    }
    else {
        std::wcerr << L"Failed to retrieve scanner path!" << std::endl;
    }
}