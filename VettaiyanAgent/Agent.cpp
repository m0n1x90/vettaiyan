#include "Agent.h"
#include "Log.h"
#include "Notification.h"
#include "YaraScanner.h"
#include "Support.h"
#include "Utils.h"
#include "DbUtil.h"

SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE                g_CurrentPipe = INVALID_HANDLE_VALUE;
HANDLE                g_WorkerThread = nullptr;

std::queue<std::wstring> g_scanQueue;
CRITICAL_SECTION g_queueLock;
HANDLE g_queueEvent = NULL;

void EnqueuePath(const std::wstring& path) {
    EnterCriticalSection(&g_queueLock);
    g_scanQueue.push(path);
    LeaveCriticalSection(&g_queueLock);
    SetEvent(g_queueEvent);
}

void EnqueueFilesInDirectory(const std::wstring& directory) {
    std::wstring searchPath = directory + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = directory + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EnqueueFilesInDirectory(fullPath);
        }
        else {
            EnqueuePath(fullPath);
        }

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

bool DequeuePath(std::wstring& pathOut) {
    EnterCriticalSection(&g_queueLock);
    if (g_scanQueue.empty()) {
        LeaveCriticalSection(&g_queueLock);
        return false;
    }
    pathOut = g_scanQueue.front();
    g_scanQueue.pop();
    LeaveCriticalSection(&g_queueLock);
    return true;
}


DWORD WINAPI ScannerWorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        WaitForSingleObject(g_queueEvent, INFINITE);

        std::wstring path;
        while (DequeuePath(path)) {
            YaraScanResult scanResult = ScanFileWithYara(path);

            if (scanResult.matched) {
                SaveScanResultToDB(scanResult);
                std::vector<std::wstring> toastArgs = {
                    L"detected",
                    L"Threat Found",
                    scanResult.reason,
                };
                LaunchNotification(toastArgs);
            }
            /*else {
                std::vector<std::wstring> toastArgs = {
                    L"No Threat Found",
                    scanResult.reason,
                };
                LaunchNotification(toastArgs);
            }*/
        }
    }
    return 0;
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    LaunchNotification(START_MSG);
    LogMessage(L"[ VettaiyanAgent ] Service Start Toasted");

    if (!InitializeYara()) {
        LogMessage(L"[ VettaiyanAgent ] Failed to initialize YARA from Service Worker");
        return ERROR_INTERNAL_ERROR;
    }

    InitializeCriticalSection(&g_queueLock);
    g_queueEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    CreateThread(NULL, 0, ScannerWorkerThread, NULL, 0, NULL);

    LogMessage(L"[ VettaiyanAgent ] YARA init passed");
    HANDLE pipe;
    wchar_t buffer[512];

    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;

    LPCWSTR sddl = L"D:(A;OICI;GRGW;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        LogMessage(L"[ VettaiyanAgent ] Failed to convert SDDL string to security descriptor");
        return ERROR_ACCESS_DENIED;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {

        pipe = CreateNamedPipe(
            SCANNER_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            sizeof(buffer),
            sizeof(buffer),
            0,
            &sa
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            LogMessage(L"[ VettaiyanAgent ] Failed to create named pipe!");
            Sleep(1000);
            continue;
        }

        g_CurrentPipe = pipe;

        BOOL connected = ConnectNamedPipe(pipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            DWORD bytesRead;
            if (ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                std::wstring receivedPath(buffer, bytesRead / sizeof(wchar_t));
                LogMessage(L"[ VettaiyanAgent ] Received: " + receivedPath);

                if (PathIsDirectoryW(receivedPath.c_str())) {
                    EnqueueFilesInDirectory(receivedPath);
                }
                else {
                    EnqueuePath(receivedPath);
                }
            }
        }

        CloseHandle(pipe);
        g_CurrentPipe = INVALID_HANDLE_VALUE;
    }

    FinalizeYara();
    LaunchNotification(STOP_MSG);
    DeleteCriticalSection(&g_queueLock);
    CloseHandle(g_queueEvent);
    LogMessage(L"[ VettaiyanAgent ] Service Stop Toasted");
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
