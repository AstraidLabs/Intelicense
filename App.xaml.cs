using Microsoft.UI.Xaml;

namespace Intelicense;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        if (_window is null)
        {
            _window = new MainWindow();
        }

        _window.Activate();
    }
}
