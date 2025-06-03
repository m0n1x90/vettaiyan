using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.ObjectModel;
using VettaiyanNode.Model;
using VettaiyanNode.DB;
using System;
using Microsoft.Windows.AppNotifications.Builder;
using Microsoft.Windows.AppNotifications;

namespace VettaiyanNode.Pages
{
    public sealed partial class Threats : Page
    {
        private ObservableCollection<Threat> ThreatData = new();
        private const int PageSize = 5;
        private int currentPage = 1;
        private int totalThreats = 0;
        private int totalPages = 1;

        public string CurrentPageDisplay => $"Page {currentPage} of {totalPages}";

        public Threats()
        {
            this.InitializeComponent();
            ThreatsList.ItemsSource = ThreatData;

            totalThreats = ScanResults.GetTotalThreatCount(Common.Global.dbPath);
            totalPages = Math.Max(1, (int)Math.Ceiling((double)totalThreats / PageSize));

            LoadThreatsPage(currentPage);
        }

        private void LoadThreatsPage(int page)
        {
            ThreatData.Clear();
            int offset = (page - 1) * PageSize;

            var newThreats = ScanResults.LoadRecentThreatsFromDbPaged(Common.Global.dbPath, PageSize, offset);
            foreach (var threat in newThreats)
                ThreatData.Add(threat);

            currentPage = page;

            NoThreatsBanner.Visibility = ThreatData.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            PrevButton.IsEnabled = currentPage > 1;
            NextButton.IsEnabled = currentPage < totalPages;

            Bindings.Update();
        }


        private void PreviousPage_Click(object sender, RoutedEventArgs e)
        {
            if (currentPage > 1)
            { 
                LoadThreatsPage(currentPage - 1);
            }
        }

        private void NextPage_Click(object sender, RoutedEventArgs e)
        {
            if (currentPage < totalPages)
            {
                LoadThreatsPage(currentPage + 1);
            }
        }

        private void ViewDetails_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Threat selectedThreat)
            {
                var app = (App)Application.Current;
                var mainWindow = app.m_window as MainWindow;

                if (mainWindow != null)
                {
                    var rootFrame = mainWindow.RootFrame;
                    rootFrame.Navigate(typeof(ThreatDetails), selectedThreat);
                }
            }
        }
    }
}
