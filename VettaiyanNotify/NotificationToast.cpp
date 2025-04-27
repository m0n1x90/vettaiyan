#include "Utils.h"
#include "NotificationToast.h"

DWORD TOAST_DEFAULT_EXPIRATION_TIME = 15000;
std::wstring TOAST_APP_NAME = L"Vettaiyan EDR";
std::wstring TOAST_USER_MODEL_ID = L"Vettaiyan EDR";
std::wstring TOAST_IMAGE_ICON = GetAssetPath(L"icons\\VettaiyanToastLogo.png");
WinToastTemplate::AudioOption TOAST_AUDIO_OPTION = WinToastTemplate::AudioOption::Default;

void ToastActionHandler::toastFailed() const {
    std::wcout << L"Error showing current toast" << std::endl;
    exit(5);
}

void ToastActionHandler::toastActivated() const {
    std::wcout << L"The user clicked in this toast" << std::endl;
    exit(0);
}

void ToastActionHandler::toastActivated(
    int actionIndex
) const {
    std::wcout << L"The user clicked on action #" << actionIndex << std::endl;
    exit(16 + actionIndex);
}

void ToastActionHandler::toastActivated(
    std::wstring response
) const {
    std::wcout << L"The user replied with: " << response << std::endl;
    exit(0);
}

void ToastActionHandler::toastDismissed(
    WinToastDismissalReason state
) const {
    switch (state) {
    case UserCanceled:
        std::wcout << L"The user dismissed this toast" << std::endl;
        exit(1);
        break;
    case TimedOut:
        std::wcout << L"The toast has timed out" << std::endl;
        exit(2);
        break;
    case ApplicationHidden:
        std::wcout << L"The application hid the toast using ToastNotifier.hide()" << std::endl;
        exit(3);
        break;
    default:
        std::wcout << L"Toast not activated" << std::endl;
        exit(4);
        break;
    }
}

int ToastDisplayer::popNormalToast(
    std::wstring toastCaptionText,
    std::wstring toastAttributeText
) {

    if (!WinToast::isCompatible()) {
        std::wcerr << L"Error, your system in not supported!" << std::endl;
        return Results::SystemNotSupported;
    }
    WinToast::instance()->setAppName(TOAST_APP_NAME);
    WinToast::instance()->setAppUserModelId(TOAST_USER_MODEL_ID);
    if (!WinToast::instance()->initialize()) {
        std::wcerr << L"Error, your system in not compatible!" << std::endl;
        return Results::InitializationFailure;
    }
    WinToastTemplate templ(WinToastTemplate::Text04);
    templ.setAudioOption(TOAST_AUDIO_OPTION);

    templ.setTextField(toastCaptionText, WinToastTemplate::FirstLine);
    templ.setAttributionText(toastAttributeText);

    if (WinToast::instance()->showToast(templ, new ToastActionHandler()) < 0) {
        std::wcerr << L"Could not launch your toast notification!";
        return Results::ToastFailed;
    }

    Sleep(TOAST_DEFAULT_EXPIRATION_TIME);
    exit(2);
}

int ToastDisplayer::popImageToast(
    std::wstring toastCaptionText, 
    std::wstring toastAttributeText
){

    if (!WinToast::isCompatible()) {
        std::wcerr << L"Error, your system in not supported!" << std::endl;
        return Results::SystemNotSupported;
    }
    WinToast::instance()->setAppName(TOAST_APP_NAME);
    WinToast::instance()->setAppUserModelId(TOAST_USER_MODEL_ID);
    if (!WinToast::instance()->initialize()) {
        std::wcerr << L"Error, your system in not compatible!" << std::endl;
        return Results::InitializationFailure;
    }
    WinToastTemplate templ(WinToastTemplate::ImageAndText02);
    templ.setAudioOption(TOAST_AUDIO_OPTION);
    templ.setImagePath(TOAST_IMAGE_ICON);

    templ.setTextField(toastCaptionText, WinToastTemplate::FirstLine);
    templ.setAttributionText(toastAttributeText);

    if (WinToast::instance()->showToast(templ, new ToastActionHandler()) < 0) {
        std::wcerr << L"Could not launch your toast notification!";
        return Results::ToastFailed;
    }

    Sleep(TOAST_DEFAULT_EXPIRATION_TIME);
    exit(2);
}