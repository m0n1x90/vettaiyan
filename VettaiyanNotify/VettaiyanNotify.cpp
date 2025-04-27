#include "wintoastlib.h"
#include <iostream>

using namespace WinToastLib;

class MyToastHandler : public IWinToastHandler {
public:
    void toastActivated() const override {
        std::wcout << L"Toast clicked!" << std::endl;
    }

    void toastDismissed(WinToastDismissalReason state) const override {
        std::wcout << L"Toast dismissed: " << state << std::endl;
    }

    void toastFailed() const override {
        std::wcout << L"Toast failed!" << std::endl;
    }
};

int main() {
    if (!WinToast::isCompatible()) {
        std::wcerr << L"Error: Not compatible with WinToast." << std::endl;
        return 1;
    }

    WinToast& toast = WinToast::instance();
    toast.setAppName(L"Test Toast App");
    const auto aumi = WinToast::configureAUMI(L"MyCompany", L"ToastApp", L"Test", L"1.0");
    toast.setAppUserModelId(aumi);

    if (!toast.initialize()) {
        std::wcerr << L"Could not initialize WinToast." << std::endl;
        return 1;
    }

    WinToastTemplate templ(WinToastTemplate::Text02);
    templ.setTextField(L"Hello, World!", WinToastTemplate::FirstLine);
    templ.setTextField(L"This is a toast from WinToast!", WinToastTemplate::SecondLine);

    MyToastHandler* handler = new MyToastHandler();
    if (toast.showToast(templ, handler) < 0) {
        std::wcerr << L"Failed to show toast." << std::endl;
        delete handler;
        return 1;
    }

    // Keep running while toast is showing
    std::wcout << L"Toast shown. Waiting..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}
