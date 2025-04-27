#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include <string>
#include <vector>

#include <windows.h>
#include <Wtsapi32.h>
#include <Userenv.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

const std::wstring NOTIFY_EXE = L"VettaiyanNotify.exe";

void LaunchNotification(const std::vector<std::wstring>& args);

#endif