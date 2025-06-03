using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using VettaiyanNode.Model;

namespace VettaiyanNode.Pages
{
    public sealed partial class ThreatDetails : Page
    {
        public Threat Threat { get; set; }

        public ThreatDetails()
        {
            this.InitializeComponent();
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            if (e.Parameter is Threat t)
            {
                Threat = t;
                Bindings.Update();
            }
        }
    }
}
