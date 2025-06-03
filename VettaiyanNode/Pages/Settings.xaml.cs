using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace VettaiyanNode.Pages
{
    public sealed partial class Settings : Page
    {
        public Settings()
        {
            this.InitializeComponent();
        }

        private void cmbTheme_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            (App.Current as App).AppThemeService.OnThemeComboBoxSelectionChanged(sender);
        }

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            (App.Current as App).AppThemeService.SetThemeComboBoxDefaultItem(cmbTheme);
        }
    }
}
