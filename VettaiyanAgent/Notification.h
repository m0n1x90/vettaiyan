#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include <string>
#include <vector>

#include <windows.h>
#include <Userenv.h>
#include <Wtsapi32.h>

#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")

const std::vector<std::wstring> START_MSG = {
    L"default",
    L"Agent Started",
    L"Vettaiyan agent is running now",
};

const std::vector<std::wstring> STOP_MSG = {
     L"default",
    L"Agent Stopped",
    L"Vettaiyan agent has been stopped",
};

void LaunchNotification(const std::vector<std::wstring>& args);

#endif