#ifndef NOTIFICATION_TOAST_H
#define NOTIFICATION_TOAST_H

#include <string>
#include "wintoastlib.h"

using namespace WinToastLib;

extern std::wstring TOAST_APP_NAME;
extern std::wstring TOAST_USER_MODEL_ID;
extern DWORD TOAST_DEFAULT_EXPIRATION_TIME;
extern WinToastTemplate::AudioOption TOAST_AUDIO_OPTION;

// PACKAGE DEFAULTS
enum Results {
    ToastClicked,             // user clicked on the toast
    ToastDismissed,           // user dismissed the toast
    ToastTimeOut,             // toast timed out
    ToastHided,               // application hid the toast
    ToastNotActivated,        // toast was not activated
    ToastFailed,              // toast failed
    SystemNotSupported,       // system does not support toasts
    UnhandledOption,          // unhandled option
    MultipleTextNotSupported, // multiple texts were provided
    InitializationFailure,    // toast notification manager initialization failure
    ToastNotLaunched          // toast could not be launched
};

class ToastActionHandler : public IWinToastHandler {
public:
    void toastFailed() const override;
    void toastActivated() const override;
    void toastActivated(int actionIndex) const override;
    void toastActivated(std::wstring response) const override;
    void toastDismissed(WinToastDismissalReason state) const override;
};

class ToastDisplayer {
public:
    static int popImageToast(std::wstring toastCaptionText, std::wstring toastAttributeText);
    static int popNormalToast(std::wstring toastCaptionText, std::wstring toastAttributeText);
};

#endif