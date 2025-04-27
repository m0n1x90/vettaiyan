#include "Scanner.h"

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "No file path provided!" << std::endl;
        return 1;
    }

    std::wstring filePath(argv[1], argv[1] + strlen(argv[1]));

    wchar_t absolutePath[MAX_PATH];
    if (GetFullPathNameW(filePath.c_str(), MAX_PATH, absolutePath, NULL) == 0) {
        std::cerr << "Failed to get the absolute path!" << std::endl;
        return 1;
    }
    std::wcout << L"Scanning file: " << absolutePath << std::endl;

    HANDLE pipe = CreateFile(
        SCANNER_PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (pipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open named pipe!" << std::endl;
        return 1;
    }

    DWORD written;
    WriteFile(pipe, absolutePath, (DWORD)(wcslen(absolutePath) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(pipe);

    return 0;
}
