#include "wintoastlib.h"
#include "NotificationToast.h"

#include <string>
#include <iostream>
#include <windows.h>

using namespace WinToastLib;

void print_help() {
    std::wcout << L"Usage: VettaiyanNotify.exe <title> <message> [image]\n"
        << L"Example:\n"
        << L"  VettaiyanNotify.exe \"Service Started\" \"Vettaiyan agent is running now\"\n"
        << L"  VettaiyanNotify.exe \"Alert\" \"Something happened!\" image\n";
}

int wmain(int argc, LPWSTR* argv) {
    if (argc < 3) {
        print_help();
        return 0;
    }

    std::wstring title = argv[1];
    std::wstring message = argv[2];
    bool useImage = (argc >= 4 && _wcsicmp(argv[3], L"image") == 0);

    if (useImage) {
        ToastDisplayer::popImageToast(title, message);
    }
    else {
        ToastDisplayer::popNormalToast(title, message);
    }

    return 0;
}
