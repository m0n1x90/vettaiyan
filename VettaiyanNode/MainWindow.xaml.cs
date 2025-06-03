using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace VettaiyanNode
{
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            this.InitializeComponent();

            contentFrame.Navigate(typeof(VettaiyanNode.Pages.Dashboard));
            navMenu.SelectionChanged += navMenuSelectionChanged;
            navMenu.BackRequested += BackButton_Click;
            contentFrame.Navigated += ContentFrame_Navigated;

            UpdateBackButton();
        }

        public Frame RootFrame => contentFrame;

        private void BackButton_Click(NavigationView sender, NavigationViewBackRequestedEventArgs args)
        {
            if (contentFrame.CanGoBack)
            {
                contentFrame.GoBack();
            }
        }

        private void ContentFrame_Navigated(object sender, NavigationEventArgs e)
        {
            UpdateBackButton();
        }

        private void UpdateBackButton()
        {
            navMenu.IsBackEnabled = contentFrame.CanGoBack;
        }

        private void navMenuSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.IsSettingsSelected)
            {
                contentFrame.Navigate(typeof(VettaiyanNode.Pages.Settings));
                return;
            }

            if (args.SelectedItemContainer is NavigationViewItem selectedItem)
            {
                switch (selectedItem.Tag)
                {
                    case "dashboard":
                        contentFrame.Navigate(typeof(VettaiyanNode.Pages.Dashboard));
                        break;
                    case "threats":
                        contentFrame.Navigate(typeof(VettaiyanNode.Pages.Threats));
                        break;
                    case "scan":
                        contentFrame.Navigate(typeof(VettaiyanNode.Pages.Scan));
                        break;
                }
            }
        }
    }
}
