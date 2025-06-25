#include "Log.h"
#include "Utils.h"
#include "Notification.h"

void LaunchNotification(const std::vector<std::wstring>& toastData) {

    if (toastData.size() < 3) return;

    std::wstring typeEncoded = UrlEncode(toastData[0]);
    std::wstring titleEncoded = UrlEncode(toastData[1]);
    std::wstring messageEncoded = UrlEncode(toastData[2]);

    std::wstring uri = L"vettaiyan://toast?type="+typeEncoded+L"&title="+titleEncoded+L"&message="+messageEncoded;

    DWORD sessionId = WTSGetActiveConsoleSessionId();
    HANDLE userToken = nullptr;

    if (!WTSQueryUserToken(sessionId, &userToken)) {
        LogMessage(L"[!] WTSQueryUserToken failed");
        return;
    }

    HANDLE duplicatedToken = nullptr;
    if (!DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &duplicatedToken)) {
        CloseHandle(userToken);
        LogMessage(L"[!] DuplicateTokenEx failed");
        return;
    }

    LPVOID env = nullptr;
    if (!CreateEnvironmentBlock(&env, duplicatedToken, FALSE)) {
        LogMessage(L"[!] CreateEnvironmentBlock failed");
        CloseHandle(duplicatedToken);
        CloseHandle(userToken);
        return;
    }

    std::wstring commandLine = L"explorer.exe \"" + uri + L"\"";

    STARTUPINFO si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    PROCESS_INFORMATION pi;

    BOOL result = CreateProcessAsUserW(
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
    );

    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        LogMessage(L"[!] CreateProcessAsUser failed to launch toast");
    }

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(duplicatedToken);
    CloseHandle(userToken);

}



