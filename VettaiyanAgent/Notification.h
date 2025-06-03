#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>

#include <windows.h>
#include <Wtsapi32.h>
#include <Userenv.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

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


std::wstring UrlEncode(const std::wstring& value);

void LaunchNotification(const std::vector<std::wstring>& args);

#endif