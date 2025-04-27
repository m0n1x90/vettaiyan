#include "Utils.h"
#include "Support.h"

void LogMessage(const std::wstring& message) {

    std::wstring logFilePath = GetExecutableDir() + LOG_FILE;
    std::wofstream logFile(logFilePath, std::ios_base::app);

    if (logFile.is_open()) {
        std::time_t now = std::time(nullptr);
        std::tm localTime;
        localtime_s(&localTime, &now);
        logFile << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L" - " << message << std::endl;
        logFile.close();
    }
}

void AddContextMenuEntry() {
    HKEY hKey;
    std::wstring keyPath = YARA_REGISTRY_CONTEXT;
    std::wstring commandPath = keyPath + L"\\command";

    wchar_t exePath[MAX_PATH];
    LoadPathIntoBuffer(SCANNER_EXECUTABLE, exePath, MAX_PATH);

    if (RegCreateKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str(), &hKey) == ERROR_SUCCESS) {
        std::wstring menuText = L"Scan with Vettaiyan (YARA)";
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)menuText.c_str(), (menuText.size() + 1) * sizeof(wchar_t));

        std::wstring iconPath = GetAssetPath(L"Assets\\icons\\VettaiyanLogo.ico");
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), (iconPath.size() + 1) * sizeof(wchar_t));

        RegCloseKey(hKey);
        LogMessage(L"[+] YARA registry context created");
    }
    else {
        LogMessage(L"[-] Failed to create registry key for menu");
    }

    if (RegCreateKeyW(HKEY_LOCAL_MACHINE, commandPath.c_str(), &hKey) == ERROR_SUCCESS) {

        std::wstring command = L"\"" + std::wstring(exePath) + L"\" \"%1\"";
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)command.c_str(), (command.size() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);

        LogMessage(L"[+] YARA command key created");
    }
    else {
        LogMessage(L"[+] Failed to create registry key for command");
    }
}

void RemoveContextMenuEntry() {
    std::wstring keyPath = YARA_REGISTRY_CONTEXT;
    if (SHDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str()) != ERROR_SUCCESS) {
        LogMessage(L"[+] Failed to delete registry context");
    }
}
