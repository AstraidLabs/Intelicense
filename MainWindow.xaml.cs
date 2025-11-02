using Intelicense.Services;
using Intelicense.ViewModels;
using Microsoft.UI.Xaml;

namespace Intelicense;

public sealed partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; }

    public MainWindow()
    {
        InitializeComponent();
        ViewModel = new MainViewModel(
            new WindowsLicenseService(),
            new DialogService(this),
            new FileService(this),
            new ClipboardService());
        DataContext = ViewModel;
    }
}
