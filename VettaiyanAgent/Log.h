#ifndef LOG_H
#define LOG_H

#include <string>
#include <fstream>
#include <iomanip>

#define LOG_FILE L"\\VettaiyanLogFile.log"

void LogMessage(const std::wstring& message);

#endif