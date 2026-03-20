#include "Log.h"
#include "Utils.h"
#include "Notification.h"
#include "Agent.h"
#include "WebServer.h"

void LaunchNotification(const std::vector<std::wstring>& toastData) {

    if (toastData.size() < 3) return;

    // Broadcast to SSE clients (web dashboard)
    std::string type(toastData[0].begin(), toastData[0].end());
    std::string title(toastData[1].begin(), toastData[1].end());
    std::string message(toastData[2].begin(), toastData[2].end());
    BroadcastNotification(type, title, message);

    // Also send to named pipe for any external listeners
    std::wstring pipeMsg = toastData[0] + L"|" + toastData[1] + L"|" + toastData[2];

    HANDLE hPipe = CreateFileW(
        NOTIFY_PIPE_NAME,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hPipe, pipeMsg.c_str(), (DWORD)(pipeMsg.size() * sizeof(wchar_t)), &bytesWritten, nullptr);
        CloseHandle(hPipe);
    }

    // LogMessage(L"[ Notification ] Sent: " + toastData[1]);
}
