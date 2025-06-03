using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VettaiyanNode.DB;
using System.IO.Pipes;
using System.Text;

namespace VettaiyanNode.Pages
{
    public sealed partial class Scan : Page
    {
        private string selectedScanType = "Quick Scan";

        public Scan()
        {
            this.InitializeComponent();
            _ = LoadScanStatisticsAsync();
        }

        private async Task LoadScanStatisticsAsync()
        {
            var (timestamp, scanType, duration, threatsFound, filesScanned) = await ScanStats.GetLatestScanAsync();
            LastScanTimeText.Text = timestamp;
            LastScanTypeText.Text = scanType;
            if (TimeSpan.TryParse(duration, out TimeSpan timeSpanDuration))
            {
                string formattedDuration = FormatTimeSpan(timeSpanDuration);
                TimeElapsedText.Text = duration;
            }
            else
            {
                TimeElapsedText.Text = "N/A";
                Console.WriteLine($"Warning: Could not parse duration '{duration}' into a TimeSpan.");
            }
            //ThreatsFoundText.Text = $"{threatsFound} threats found";
            //FilesScannedText.Text = $"{filesScanned} files";
        }

        private string FormatTimeSpan(TimeSpan duration)
        {
            List<string> parts = new List<string>();

            if (duration.Days > 0)
            {
                parts.Add($"{duration.Days} day{(duration.Days == 1 ? "" : "s")}");
            }
            if (duration.Hours > 0)
            {
                parts.Add($"{duration.Hours} hour{(duration.Hours == 1 ? "" : "s")}");
            }
            if (duration.Minutes > 0)
            {
                parts.Add($"{duration.Minutes} minute{(duration.Minutes == 1 ? "" : "s")}");
            }
            if (duration.TotalSeconds > 0 && parts.Count == 0 || (duration.Seconds > 0 && parts.Count > 0))
            {
                parts.Add($"{duration.Seconds} second{(duration.Seconds == 1 ? "" : "s")}");
            }
            if (parts.Count == 0 && duration.TotalMilliseconds > 0)
            {
                parts.Add($"{duration.TotalMilliseconds:F0} ms");
            }

            if (parts.Count == 0)
            {
                return "0 seconds";
            }
            else if (parts.Count == 1)
            {
                return parts[0];
            }
            else
            {
                string lastPart = parts[parts.Count - 1];
                parts.RemoveAt(parts.Count - 1);
                return string.Join(", ", parts) + " and " + lastPart;
            }
        }

        private void ScanRadioButtonChecked(object sender, SelectionChangedEventArgs e)
        {
            if (ScanOptions.SelectedItem is StackPanel panel && panel.Children[0] is TextBlock textBlock)
            {
                selectedScanType = textBlock.Text;
            }
        }

        private async void ScanButtonClick(object sender, RoutedEventArgs e)
        {
            ScanButton.Visibility = Visibility.Collapsed;
            ScanProgressBar.Visibility = Visibility.Visible;

            switch (selectedScanType)
            {
                case "Quick Scan":
                    await PerformQuickScan();
                    break;
                case "Full Scan":
                    await PerformFullScan();
                    break;
                case "Custom Scan":
                    await PerformCustomScan();
                    break;
            }

            ScanProgressBar.Visibility = Visibility.Collapsed;
            ScanButton.Visibility = Visibility.Visible;
            await LoadScanStatisticsAsync();
        }

        private async Task PerformQuickScan()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            await PerformScan(new[] { userProfile }, "Quick Scan");
        }


        private async Task PerformFullScan()
        {
            List<string> rootDirs = new();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                {
                    rootDirs.Add(drive.RootDirectory.FullName);
                }
            }

            await PerformScan(rootDirs, "Full Scan");
        }

        private async Task PerformCustomScan()
        {
            var folderPicker = new FolderPicker
            {
                SuggestedStartLocation = PickerLocationId.Downloads
            };

            folderPicker.FileTypeFilter.Add("*");

            var window = (App.Current as App)?.m_window;
            if (window == null)
            {
                Console.WriteLine("[Error] App.m_window is null. Cannot open folder picker.");
                return;
            }

            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            WinRT.Interop.InitializeWithWindow.Initialize(folderPicker, hwnd);

            StorageFolder folder = await folderPicker.PickSingleFolderAsync();
            if (folder != null)
            {
                Console.WriteLine($"[Custom Scan] Selected folder: {folder.Path}");
                await PerformScan(new[] { folder.Path }, "Custom Scan");
            }
            else
            {
                Console.WriteLine("[Custom Scan] No folder was selected.");
            }
        }

        private async Task PerformScan(IEnumerable<string> directories, string scanType)
        {
            int threatsFound = 0;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            int scannedFileCount = 0;

            Console.WriteLine($"[UI] {scanType}");

            foreach (var dir in directories)
            {
                try
                {
                    using var pipeClient = new NamedPipeClientStream(
                        ".",
                        "VettaiyanScanner",
                        PipeDirection.InOut,
                        PipeOptions.Asynchronous
                    );

                    await pipeClient.ConnectAsync(2000);

                    byte[] buffer = Encoding.Unicode.GetBytes(dir);
                    await pipeClient.WriteAsync(buffer, 0, buffer.Length);
                    await pipeClient.FlushAsync();

                    Console.WriteLine($"[Sent Directory] {dir}");

                    // Start listening for agent updates
                    var readBuffer = new byte[512];
                    bool agentDone = false;

                    while (!agentDone)
                    {
                        int bytesRead = await pipeClient.ReadAsync(readBuffer, 0, readBuffer.Length);
                        if (bytesRead > 0)
                        {
                            string message = Encoding.Unicode.GetString(readBuffer, 0, bytesRead).Trim();
                            Console.WriteLine($"[Agent Raw Message] '{message}'");

                            if (message.StartsWith("Scanned:"))
                            {
                                string numberPart = message["Scanned:".Length..].Trim();
                                if (int.TryParse(numberPart, out int count))
                                {
                                    scannedFileCount = count;
                                   
                                    DispatcherQueue.TryEnqueue(() =>
                                    {
                                        //FilesScannedText.Text = $"{scannedFileCount} files";
                                        ScanProgressBar.Value = scannedFileCount % 100;
                                        //ThreatsFoundText.Text = "Scanning...";
                                    });
                                }
                                else
                                {
                                    Console.WriteLine($"[Warning] Could not parse scanned count from: {message}");
                                }
                            }
                            else if (message.StartsWith("Done"))
                            {
                                agentDone = true;
                                DispatcherQueue.TryEnqueue(() =>
                                {
                                    //ThreatsFoundText.Text = "Scan complete";
                                });
                            }
                            else
                            {
                                Console.WriteLine($"[Info] Agent sent unrecognized message: {message}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("[Agent] Pipe closed or EOF");
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException uaex)
                {
                    Console.WriteLine($"[Access Denied] Cannot scan {dir}: {uaex.Message}");
                    continue;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Pipe Error] Failed to scan {dir}: {ex.Message}");
                }
            }

            stopwatch.Stop();

            // Wait briefly to ensure DB is written
            await Task.Delay(1000);

            var (_, _, _, agentThreats, _) = await ScanStats.GetLatestScanAsync();
            threatsFound = int.TryParse(agentThreats, out int result) ? result : 0;

            DispatcherQueue.TryEnqueue(() =>
            {
                //ThreatsFoundText.Text = $"{threatsFound} threats found";
                //FilesScannedText.Text = $"{scannedFileCount} files";
            });

            await ScanStats.SaveScanAsync(scanType, stopwatch.Elapsed.ToString(), threatsFound.ToString(), scannedFileCount.ToString());
        }

    }
}
