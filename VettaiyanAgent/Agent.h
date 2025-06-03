#ifndef AGENT_H
#define AGENT_H

#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <iostream>
#include <windows.h>
#include <sddl.h>
#include <shlwapi.h>
#include <processthreadsapi.h>

#pragma comment(lib, "shlwapi.lib")

const std::wstring SERVICE_NAME = L"Vettaiyan";

#define SCANNER_PIPE_NAME L"\\\\.\\pipe\\VettaiyanScanner"

#endif