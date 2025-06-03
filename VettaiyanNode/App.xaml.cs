using DevWinUI;
using System;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;
using System.Runtime.InteropServices;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;
using CommunityToolkit.WinUI.Notifications;
using System.Diagnostics;
using System.Data.Entity;

namespace VettaiyanNode
{
    internal static class WindowHelper
    {
        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        public static void ShowWindow(Window window)
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            ShowWindow(hwnd, 0x00000009); // SW_RESTORE
            SetForegroundWindow(hwnd);
        }
    }

    public partial class App : Application
    {
        public Window m_window { get; private set; }
        public IThemeService AppThemeService { get; set; }
        public static DispatcherQueue DispatcherQueue { get; private set; }

        public App()
        {
            this.InitializeComponent();
        }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            DispatcherQueue = global::Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
            ToastNotificationManagerCompat.OnActivated += ToastNotificationManagerCompat_OnActivated;
            AppInstance currentInstance = AppInstance.GetCurrent();
            currentInstance.Activated += App_Activated;
            AppActivationArguments activationArgs = currentInstance.GetActivatedEventArgs();

            if (activationArgs.Kind == ExtendedActivationKind.Protocol)
            {
                HandleProtocolActivation(activationArgs.Data as ProtocolActivatedEventArgs);
            }
            else
            {
                if (!ToastNotificationManagerCompat.WasCurrentProcessToastActivated())
                {
                    LaunchAndBringToForegroundIfNeeded();
                }
            }
        }

        private void App_Activated(object sender, AppActivationArguments args)
        {
            if (m_window != null)
            {
                m_window.DispatcherQueue.TryEnqueue(() =>
                {
                    WindowHelper.ShowWindow(m_window);
                    if (args.Kind == ExtendedActivationKind.Protocol)
                    {
                        HandleProtocolActivation(args.Data as ProtocolActivatedEventArgs);
                    }
                });
            }
            else
            {
                LaunchAndBringToForegroundIfNeeded();
                if (args.Kind == ExtendedActivationKind.Protocol)
                {
                    HandleProtocolActivation(args.Data as ProtocolActivatedEventArgs);
                }
            }
        }

        private void LaunchAndBringToForegroundIfNeeded()
        {
            if (m_window == null)
            {
                m_window = new MainWindow();
                m_window.Activate();

                DB.Init.Initialize();

                AppThemeService = new ThemeService();
                AppThemeService.Initialize(m_window);
                AppThemeService.SetBackdropType(BackdropType.None);
            }

            WindowHelper.ShowWindow(m_window);
        }

        private void ToastNotificationManagerCompat_OnActivated(ToastNotificationActivatedEventArgsCompat e)
        {
            var dispatcherQueue = m_window?.DispatcherQueue ?? App.DispatcherQueue;

            dispatcherQueue.TryEnqueue(delegate
            {
                var args = ToastArguments.Parse(e.Argument);

                switch (args["action"])
                {
                    // Send a background message.
                    case "sendMessage":
                        string message = e.UserInput["textBox"].ToString();
                        // TODO: Send it.
                        LogToFile($"[ToastActivation] Message sent: {message}");

                        // If the UI app isn't open.
                        if (m_window == null)
                        {
                            // Close since we're done.
                            Process.GetCurrentProcess().Kill();
                        }

                        break;

                    // View a message.
                    case "viewMessage":
                        // Launch/bring window to foreground.
                        LaunchAndBringToForegroundIfNeeded();
                        LogToFile("[ToastActivation] View message action triggered.");
                        // TODO: Open the message.
                        break;
                }
            });
        }

        private void HandleProtocolActivation(ProtocolActivatedEventArgs args)
        {
            try
            {
                if (args == null)
                {
                    LogToFile("[ProtocolActivation] ProtocolActivatedEventArgs is null.");
                    return;
                }

                Uri uri = args.Uri;
                LogToFile($"[ProtocolActivation] URI: {uri}");

                string path = uri.Host.ToLower();
                switch (path)
                {
                    case "toast":
                        string type = Common.Util.GetQueryParam(uri, "type") ?? "<null>";
                        string title = Common.Util.GetQueryParam(uri, "title") ?? "<null>";
                        string message = Common.Util.GetQueryParam(uri, "message") ?? "<null>";
                        switch (type)
                        {
                            case "detected":
                                Common.Notification.ShowDetectionToast(title, message);
                                break;

                            default:
                                Common.Notification.ShowDefaultToast(title, message);
                                break;
                        }
                        LogToFile($"[ProtocolActivation] Shown Toast: Title={title}, Message={message}");
                        break;

                    case "scan":
                        string target = Common.Util.GetQueryParam(uri, "target") ?? "<null>";
                        if (!string.IsNullOrEmpty(target) && target != "<null>")
                        {
                            string absolutePath = Path.GetFullPath(target);
                            LogToFile($"[ProtocolActivation] Scanning Target: {absolutePath}");

                            bool sent = Common.IPC.SendPathToScanner(absolutePath);
                            LogToFile(sent ? "[ProtocolActivation] Scan sent successfully." : "[ProtocolActivation] Failed to send scan.");
                        }
                        else
                        {
                            LogToFile("[ProtocolActivation] Scan target is empty or invalid.");
                        }
                        break;

                    default:
                        LogToFile($"[ProtocolActivation] Unknown action: {path}");
                        break;
                }
            }
            catch (Exception ex)
            {
                LogToFile($"[ProtocolActivation] Error: {ex.Message}");
            }
        }

        private void ShowCustomToast(string title, string message)
        {
            new ToastContentBuilder()
                .AddText(title)
                .AddInputTextBox("textBox", message) // Added ID for the input textbox
                .AddButton(new ToastButton()
                    .SetContent("Send")
                    .AddArgument("action", "sendMessage"))
                .Show();
        }

        private void LogToFile(string message)
        {
            try
            {
                string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "VettaiyanAppLog.txt");
                // Ensure the directory exists before writing the file
                string logDirectory = Path.GetDirectoryName(logPath);
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}");
            }
            catch (Exception ex)
            {
                // Log to debug output or console if file logging fails, to prevent silent failures.
                Debug.WriteLine($"[LogToFile Error] Could not write to log file: {ex.Message}");
            }
        }
    }
}
