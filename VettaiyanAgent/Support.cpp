#include "Log.h"
#include "Utils.h"
#include "Support.h"

void AddContextMenuEntry() {

    HKEY hKey;
    std::wstring keyPath = YARA_REGISTRY_CONTEXT;
    std::wstring commandPath = keyPath + L"\\command";

    if (RegCreateKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str(), &hKey) == ERROR_SUCCESS) {
        std::wstring menuText = L"Scan with Vettaiyan (YARA)";
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)menuText.c_str(), (menuText.size() + 1) * sizeof(wchar_t));

        std::wstring iconPath = GetAssetPath(L"Assets\\icons\\VettaiyanLogo.ico");
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)iconPath.c_str(), (iconPath.size() + 1) * sizeof(wchar_t));

        RegCloseKey(hKey);
        LogMessage(L"[ VettaiyanAgent ] YARA registry context created");
    }
    else {
        LogMessage(L"[ VettaiyanAgent ] Failed to create registry key for menu");
    }

    if (RegCreateKeyW(HKEY_LOCAL_MACHINE, commandPath.c_str(), &hKey) == ERROR_SUCCESS) {

        std::wstring command = L"explorer \"vettaiyan://scan?target=%1\"";
        RegSetValueExW(hKey, nullptr, 0, REG_SZ, (const BYTE*)command.c_str(), (command.size() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);

        LogMessage(L"[ VettaiyanAgent ] YARA command key created");
    }
    else {
        LogMessage(L"[ VettaiyanAgent ] Failed to create registry key for command");
    }

}

void RemoveContextMenuEntry() {

    std::wstring keyPath = YARA_REGISTRY_CONTEXT;
    if (SHDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str()) != ERROR_SUCCESS) {
        LogMessage(L"[ VettaiyanAgent ] Failed to delete registry context");
    }

}
