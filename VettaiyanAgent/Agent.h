#ifndef AGENT_H
#define AGENT_H

#include <string>
#include <vector>
#include <iostream>
#include <windows.h>
#include <sddl.h>
#include <processthreadsapi.h>

const std::wstring SERVICE_NAME = L"Vettaiyan";

#define SCANNER_PIPE_NAME L"\\\\.\\pipe\\VettaiyanScanner"

const std::vector<std::wstring> START_MSG = {
    L"Agent Started",
    L"Vettaiyan agent is running now",
    L"image"
};

const std::vector<std::wstring> STOP_MSG = {
    L"Agent Stopped",
    L"Vettaiyan agent has been stopped",
    L"image"
};

#endif