#include "Agent.h"
#include "Notification.h"
#include "YaraScanner.h"
#include "Support.h"
#include "Utils.h"

SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE                g_CurrentPipe = INVALID_HANDLE_VALUE;
HANDLE                g_WorkerThread = nullptr;

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {

    LaunchNotification(START_MSG);
    LogMessage(L"[+] Service Start Toasted");

    if (!InitializeYara()) {
        LogMessage(L"[-] Failed to initialize YARA");
        return ERROR_INTERNAL_ERROR;
    }
    LogMessage(L"[+] YARA init passed");
    HANDLE pipe;
    wchar_t buffer[512];

    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;

    LPCWSTR sddl = L"D:(A;OICI;GRGW;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        LogMessage(L"[-] Failed to convert SDDL string to security descriptor");
        return ERROR_ACCESS_DENIED;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {

        pipe = CreateNamedPipe(
            SCANNER_PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(buffer),
            sizeof(buffer),
            0,
            &sa
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            LogMessage(L"[-] Failed to create named pipe! Error: " + std::to_wstring(error));
            Sleep(1000);
            continue;
        }

        g_CurrentPipe = pipe;

        BOOL connected = ConnectNamedPipe(pipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            LogMessage(L"[+] Client connected. Waiting for file path...");

            DWORD bytesRead;
            if (ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                std::wstring fileToScan(buffer, bytesRead / sizeof(wchar_t));

                YaraScanResult scanResult = ScanFileWithYara(fileToScan);
                if (scanResult.matched) {
                    std::vector<std::wstring> toastArgs = {
                        L"Threat Found",
                        scanResult.reason,
                        L"image"
                    };
                    LaunchNotification(toastArgs);
                }
                else {
                    std::wcout << L"No threats found for " << fileToScan << std::endl;
                }
            }
        }

        CloseHandle(pipe);
        g_CurrentPipe = INVALID_HANDLE_VALUE;
    }

    FinalizeYara();
    LogMessage(L"[+] Cleaned YARA");

    LaunchNotification(STOP_MSG);
    LogMessage(L"[+] Service Stop Toasted");

    return ERROR_SUCCESS;
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING) break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        SetEvent(g_ServiceStopEvent);

        if (g_WorkerThread) {
            CancelSynchronousIo(g_WorkerThread);
        }
        break;

    default:
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME.c_str(), ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (g_ServiceStopEvent == nullptr) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    AddContextMenuEntry();

    g_WorkerThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (g_WorkerThread) {
        WaitForSingleObject(g_WorkerThread, INFINITE);
        CloseHandle(g_WorkerThread);
    }

    RemoveContextMenuEntry();
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int wmain() {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME.c_str()), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        return GetLastError();
    }

    return 0;
}
