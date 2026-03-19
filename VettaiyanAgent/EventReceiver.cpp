/*
 * EventReceiver.cpp - Connects to kernel sensors and processes events
 * 
 * Two threads:
 * 1. DriverEventThread: Reads events from VettaiyanDriver via IOCTL
 * 2. FilterEventThread: Reads events from VettaiyanFilter via FilterPort
 */

#include "EventReceiver.h"
#include "Log.h"

#include <winioctl.h>
#include <vector>
#include <mutex>

/* State */
static HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;
static HANDLE g_FilterPort = INVALID_HANDLE_VALUE;
static HANDLE g_DriverThread = NULL;
static HANDLE g_FilterThread = NULL;
static HANDLE g_StopEvent = NULL;

static std::vector<EventCallback> g_Callbacks;
static std::mutex g_CallbackMutex;

/* Buffer size for reading events from driver */
#define DRIVER_READ_BUFFER_SIZE (1024 * 256) /* 256KB */
#define FILTER_READ_BUFFER_SIZE (sizeof(EDR_FILE_EVENT) + sizeof(FILTER_MESSAGE_HEADER))


static void DispatchEvent(const EDR_EVENT_HEADER* header, const void* data, ULONG size)
{
    std::lock_guard<std::mutex> lock(g_CallbackMutex);
    for (auto& cb : g_Callbacks) {
        cb(header, data, size);
    }
}


static DWORD WINAPI DriverEventThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    std::vector<BYTE> buffer(DRIVER_READ_BUFFER_SIZE);
    DWORD bytesReturned;

    LogMessage(L"[ EventReceiver ] Driver event thread started");

    while (WaitForSingleObject(g_StopEvent, 50) != WAIT_OBJECT_0) {
        
        if (g_DriverHandle == INVALID_HANDLE_VALUE) {
            /* Try to connect to driver */
            g_DriverHandle = CreateFileW(
                L"\\\\.\\VettaiyanEDR",
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (g_DriverHandle == INVALID_HANDLE_VALUE) {
                Sleep(5000); /* Retry every 5 seconds */
                continue;
            }

            LogMessage(L"[ EventReceiver ] Connected to VettaiyanDriver");
        }

        /* Read events via IOCTL */
        BOOL success = DeviceIoControl(
            g_DriverHandle,
            IOCTL_EDR_READ_EVENTS,
            NULL,
            0,
            buffer.data(),
            (DWORD)buffer.size(),
            &bytesReturned,
            NULL
        );

        if (!success) {
            DWORD err = GetLastError();
            if (err == ERROR_DEV_NOT_EXIST || err == ERROR_FILE_NOT_FOUND) {
                LogMessage(L"[ EventReceiver ] Driver disconnected, reconnecting...");
                CloseHandle(g_DriverHandle);
                g_DriverHandle = INVALID_HANDLE_VALUE;
            }
            continue;
        }

        if (bytesReturned == 0) continue;

        /* Parse and dispatch events from the buffer */
        ULONG offset = 0;
        while (offset < bytesReturned) {
            if (offset + sizeof(EDR_EVENT_HEADER) > bytesReturned) break;

            const EDR_EVENT_HEADER* header = (const EDR_EVENT_HEADER*)(buffer.data() + offset);
            
            if (header->EventSize == 0 || offset + header->EventSize > bytesReturned) break;

            DispatchEvent(header, buffer.data() + offset, header->EventSize);
            offset += header->EventSize;
        }
    }

    LogMessage(L"[ EventReceiver ] Driver event thread stopped");
    return 0;
}


static DWORD WINAPI FilterEventThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    LogMessage(L"[ EventReceiver ] Filter event thread started");

    BYTE msgBuffer[FILTER_READ_BUFFER_SIZE] = { 0 };
    PFILTER_MESSAGE_HEADER msgHeader = (PFILTER_MESSAGE_HEADER)msgBuffer;

    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0) {
        
        if (g_FilterPort == INVALID_HANDLE_VALUE) {
            /* Try to connect to filter port */
            HRESULT hr = FilterConnectCommunicationPort(
                EDR_FILTER_PORT_NAME,
                0,
                NULL,
                0,
                NULL,
                &g_FilterPort
            );

            if (FAILED(hr)) {
                Sleep(5000); /* Retry every 5 seconds */
                continue;
            }

            LogMessage(L"[ EventReceiver ] Connected to VettaiyanFilter port");
        }

        /* Read file event message from filter */
        HRESULT hr = FilterGetMessage(
            g_FilterPort,
            msgHeader,
            FILTER_READ_BUFFER_SIZE,
            NULL    /* Synchronous */
        );

        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
                hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                LogMessage(L"[ EventReceiver ] Filter port disconnected, reconnecting...");
                CloseHandle(g_FilterPort);
                g_FilterPort = INVALID_HANDLE_VALUE;
            }
            continue;
        }

        /* Extract file event from message */
        EDR_FILE_EVENT* fileEvent = (EDR_FILE_EVENT*)(msgBuffer + sizeof(FILTER_MESSAGE_HEADER));
        DispatchEvent(&fileEvent->Header, fileEvent, sizeof(EDR_FILE_EVENT));
    }

    LogMessage(L"[ EventReceiver ] Filter event thread stopped");
    return 0;
}


void RegisterEventCallback(EventCallback callback)
{
    std::lock_guard<std::mutex> lock(g_CallbackMutex);
    g_Callbacks.push_back(callback);
}


bool InitializeEventReceiver()
{
    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) return false;

    /* Start driver event thread */
    g_DriverThread = CreateThread(NULL, 0, DriverEventThread, NULL, 0, NULL);
    if (!g_DriverThread) {
        LogMessage(L"[ EventReceiver ] Failed to create driver event thread");
    }

    /* Start filter event thread */
    g_FilterThread = CreateThread(NULL, 0, FilterEventThread, NULL, 0, NULL);
    if (!g_FilterThread) {
        LogMessage(L"[ EventReceiver ] Failed to create filter event thread");
    }

    LogMessage(L"[ EventReceiver ] Event receiver initialized");
    return true;
}


void ShutdownEventReceiver()
{
    if (g_StopEvent) {
        SetEvent(g_StopEvent);
    }

    /* Wait for threads to finish */
    HANDLE threads[2] = { g_DriverThread, g_FilterThread };
    for (int i = 0; i < 2; i++) {
        if (threads[i]) {
            WaitForSingleObject(threads[i], 5000);
            CloseHandle(threads[i]);
        }
    }

    g_DriverThread = NULL;
    g_FilterThread = NULL;

    if (g_DriverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(g_DriverHandle);
        g_DriverHandle = INVALID_HANDLE_VALUE;
    }

    if (g_FilterPort != INVALID_HANDLE_VALUE) {
        CloseHandle(g_FilterPort);
        g_FilterPort = INVALID_HANDLE_VALUE;
    }

    if (g_StopEvent) {
        CloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }

    std::lock_guard<std::mutex> lock(g_CallbackMutex);
    g_Callbacks.clear();

    LogMessage(L"[ EventReceiver ] Shutdown complete");
}


bool GetDriverStatistics(EDR_STATISTICS* stats)
{
    if (g_DriverHandle == INVALID_HANDLE_VALUE || stats == NULL) return false;

    DWORD bytesReturned;
    BOOL success = DeviceIoControl(
        g_DriverHandle,
        IOCTL_EDR_GET_STATS,
        NULL,
        0,
        stats,
        sizeof(EDR_STATISTICS),
        &bytesReturned,
        NULL
    );

    return success && bytesReturned == sizeof(EDR_STATISTICS);
}


bool KillProcessViaDriver(ULONG processId, ULONG reason)
{
    if (g_DriverHandle == INVALID_HANDLE_VALUE) return false;

    EDR_KILL_PROCESS_REQUEST request = { 0 };
    request.ProcessId = processId;
    request.Reason = reason;

    DWORD bytesReturned;
    BOOL success = DeviceIoControl(
        g_DriverHandle,
        IOCTL_EDR_KILL_PROCESS,
        &request,
        sizeof(request),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (success) {
        LogMessage(L"[ EventReceiver ] Kill process PID=" + std::to_wstring(processId) + L" sent to driver");
    }

    return success ? true : false;
}


bool IsDriverConnected()
{
    return g_DriverHandle != INVALID_HANDLE_VALUE;
}


bool IsFilterConnected()
{
    return g_FilterPort != INVALID_HANDLE_VALUE;
}
