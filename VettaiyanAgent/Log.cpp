#include "Log.h";
#include "Utils.h"

void LogMessage(const std::wstring& message) {

    std::wstring logFilePath = GetExecutableDir() + LOG_FILE;
    std::wofstream logFile(logFilePath, std::ios_base::app);

    if (logFile.is_open()) {
        std::time_t now = std::time(nullptr);
        std::tm localTime;
        localtime_s(&localTime, &now);
        logFile << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L" - " << message << std::endl;
        logFile.close();
    }

}