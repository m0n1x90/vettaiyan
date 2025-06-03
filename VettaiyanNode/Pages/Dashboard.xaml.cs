using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;
using VettaiyanNode.DB;
using VettaiyanNode.Model;
using System.Threading.Tasks;



namespace VettaiyanNode.Pages
{
    public sealed partial class Dashboard : Page
    {
        private DispatcherTimer _threatPollTimer;
        public ObservableCollection<Threat> Threats { get; set; }

        private readonly Dictionary<TextBlock, Func<(string text, string brushKey)>> _metadataGetters;

        public Dashboard()
        {
            this.InitializeComponent();

            _metadataGetters = new Dictionary<TextBlock, Func<(string, string)>>
            {
                { EndpointText,    GetHostNameInfo },
                { OSText,          GetOSInfo       },
                { UserText,        GetUserInfo     },
                { SyncText,        GetLastSyncInfo },
                { AgentStatusText, GetAgentStatus  },
                { ThreatsBlockedText, GetThreatsBlockedInfo },
                { RealTimeProtectionText, SetRealTimeProtectionInfo },
            };
            LoadEndpointMetadata();

            Threats = new ObservableCollection<Threat>(ScanResults.LoadRecentThreatsFromDb(Common.Global.dbPath));
            ThreatListView.ItemsSource = Threats;

            Threats.CollectionChanged += (s, e) => UpdateThreatVisibility();
            UpdateThreatVisibility();

            StartThreatPolling();
        }

        private void StartThreatPolling()
        {
            _threatPollTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            _threatPollTimer.Tick += CheckForNewThreats;
            _threatPollTimer.Start();
        }

        private void CheckForNewThreats(object sender, object e)
        {
            var updated = ScanResults.LoadRecentThreatsFromDb(Common.Global.dbPath);
            if (!Threats.SequenceEqual(updated, new ThreatComparer()))
            {
                Threats.Clear();
                foreach (var threat in updated)
                    Threats.Add(threat);
            }
        }

        class ThreatComparer : IEqualityComparer<Threat>
        {
            public bool Equals(Threat x, Threat y)
            {
                return x.ThreatName == y.ThreatName &&
                       x.ThreatImageName == y.ThreatImageName &&
                       x.TimeDetected == y.TimeDetected &&
                       x.ActionTaken == y.ActionTaken;
            }

            public int GetHashCode(Threat obj)
            {
                return HashCode.Combine(obj.ThreatName, obj.ThreatImageName, obj.TimeDetected, obj.ActionTaken);
            }
        }


        private async void LoadEndpointMetadata()
        {
            var fetchingBrush = (SolidColorBrush)Application.Current.Resources["MetadataFetchingBrush"];

            foreach (var tb in _metadataGetters.Keys.Append(LastScanText))
            {
                tb.Text = "Fetching…";
                tb.Foreground = fetchingBrush;
            }

            // sync fields
            foreach (var kv in _metadataGetters)
            {
                var tb = kv.Key;
                var (text, brushKey) = kv.Value();
                tb.Text = text;
                tb.Foreground = (SolidColorBrush)Application.Current.Resources[brushKey];
            }

            // async field
            var (scanText, scanBrush) = await GetLastScanInfoAsync();
            LastScanText.Text = scanText;
            LastScanText.Foreground = (SolidColorBrush)Application.Current.Resources[scanBrush];
        }


        private (string, string) GetHostNameInfo()
        {
            try
            {
                string hostname = Environment.MachineName;
                var host = System.Net.Dns.GetHostEntry(hostname);
                var ip = host.AddressList.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString() ?? "Unavailable";
                return ($"{hostname} ({ip})", "MetadataDefaultBrush");
            }
            catch
            {
                return ("Error fetching hostname", "MetadataErrorBrush");
            }
        }

        private (string, string) GetOSInfo()
        {
            try
            {
                var key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
                string product = Registry.GetValue(key, "ProductName", "")?.ToString() ?? "";
                string version = Registry.GetValue(key, "DisplayVersion", "")?.ToString() ?? "";
                string build = Registry.GetValue(key, "CurrentBuildNumber", "")?.ToString() ?? "";
                return ($"{product} {version} (Build {build})", "MetadataDefaultBrush");
            }
            catch
            {
                return ("OS Unavailable", "MetadataErrorBrush");
            }
        }

        private (string, string) GetUserInfo()
        {
            try
            {
                return (Environment.UserName, "MetadataDefaultBrush");
            }
            catch
            {
                return ("Unavailable", "MetadataErrorBrush");
            }
        }

        private (string, string) GetLastSyncInfo()
        {
            return ("Upcoming", "MetadataErrorBrush");
        }

        private static async Task<(string, string)> GetLastScanInfoAsync()
        {
            try
            {
                var (timestamp, scanType, duration, threatsFound, filesScanned) = await ScanStats.GetLatestScanAsync();
                String LastScan = timestamp;
                return (LastScan, "MetadataDefaultBrush");
            }
            catch
            {
                return ("Unavailable", "MetadataErrorBrush");
            }
        }

        private (string, string) GetAgentStatus()
        {
            const string serviceName = "Vettaiyan";
            try
            {
                using var svc = new ServiceController(serviceName);
                return (svc.Status == ServiceControllerStatus.Running)
                    ? ("Running", "MetadataSuccessBrush")
                    : ("Stopped", "MetadataErrorBrush");
            }
            catch
            {
                return ("Not Installed", "MetadataErrorBrush");
            }
        }

        private (string, string) GetThreatsBlockedInfo()
        {
            try
            {
                String ThreatsBlocked= ScanResults.GetTotalThreatCount(Common.Global.dbPath).ToString(); 
                return (ThreatsBlocked, "MetadataDefaultBrush");
            }
            catch
            {
                return ("Unavailable", "MetadataErrorBrush");
            }
        }

        private (string, string) SetRealTimeProtectionInfo()
        {
            return ("Upcoming", "MetadataErrorBrush");
        }

        private void UpdateThreatVisibility()
        {
            if (Threats.Count == 0)
            {
                ThreatListView.Visibility = Visibility.Collapsed;
                NoThreatsBanner.Visibility = Visibility.Visible;
            }
            else
            {
                ThreatListView.Visibility = Visibility.Visible;
                NoThreatsBanner.Visibility = Visibility.Collapsed;
            }
        }

    }
}
