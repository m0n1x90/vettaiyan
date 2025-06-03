using System;
using CommunityToolkit.WinUI.Notifications;

namespace VettaiyanNode.Common
{
    public class Notification
    {
        public static void ShowDefaultToast(string title, string message)
        {
            new ToastContentBuilder()
                .AddText(title)
                .AddText(message)
                .Show();
        }

        public static void ShowMessageCaptionToast(string title, string message, string caption)
        {
            new ToastContentBuilder()
                .AddText(title)
                .AddText(message)
                .AddText(caption)
                .Show();
        }

        public static void ShowDetectionToast(string title, string message)
        {
            new ToastContentBuilder()
                .AddAppLogoOverride(new Uri("ms-appx:///Assets/Images/Detected.png"), ToastGenericAppLogoCrop.Default)
                .AddText(title)
                .AddText(message)
                .Show();
        }
    }
}
