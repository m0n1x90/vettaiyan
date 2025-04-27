#include "Notification.h"


void LaunchNotification(const std::vector<std::wstring>& args) {

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    HANDLE userToken = nullptr;

    if (!WTSQueryUserToken(sessionId, &userToken)) {
        return;
    }

    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &duplicatedToken)) {
        CloseHandle(userToken);
        return;
    }

    LPVOID env = nullptr;
    CreateEnvironmentBlock(&env, duplicatedToken, FALSE);

    std::wstring commandLine = L"\"" + NOTIFY_EXE + L"\"";
    for (const auto& arg : args) {
        commandLine += L" \"" + arg + L"\"";
    }

    STARTUPINFO si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    if (CreateProcessAsUserW(
        duplicatedToken, 
        nullptr, 
        &commandLine[0], 
        nullptr, 
        nullptr, 
        FALSE,
        CREATE_UNICODE_ENVIRONMENT, 
        env, 
        nullptr, 
        &si, 
        &pi
    )) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(duplicatedToken);
    CloseHandle(userToken);
}

