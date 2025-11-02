# WinLicenseInfo

WinLicenseInfo is a WinUI 3 desktop application that safely collects and displays Windows licensing information. The app uses legal Windows APIs, registry locations, and WMI queries to read existing license data without modifying activation state. Users can view the information in a friendly form, copy it to the clipboard, or export it to a JSON file.

## Features

- Collects license metadata from:
  - Windows registry (`CurrentVersion` and `SoftwareProtectionPlatform` keys)
  - WMI/CIM (`SoftwareLicensingProduct` and `SoftwareLicensingService` classes)
  - Win32 `GetProductInfo` API to determine the product type code
  - Optional PowerShell fallback script (disabled by user)
- Uses the MVVM pattern via `CommunityToolkit.Mvvm`.
- Presents data in labelled, read-only text boxes with busy indicator during collection.
- Tracks every data source and displays retrieval status.
- Sensitive keys (OA3 key and decoded digital product key) are only retrieved after user confirmation.
- Export collected data to a formatted JSON file or copy to the clipboard (both prompt if sensitive data is included).

## Prerequisites

- Windows 10 version 1809 or later.
- [Visual Studio 2022](https://visualstudio.microsoft.com/) with the **.NET Desktop Development** workload and the **Windows App SDK**.
- .NET 8 SDK (the project targets `net8.0-windows10.0.19041.0`).

## Building and running

1. Clone or download this repository on a Windows machine.
2. Open `Intelicense.sln` in Visual Studio 2022.
3. Restore NuGet packages if prompted.
4. Build and run the solution. The startup project is `WinLicenseInfo` (`Intelicense.csproj`).

## Usage

1. Launch the app.
2. (Optional) Leave the **Use PowerShell as fallback** checkbox enabled to allow the app to fill missing values with a PowerShell script when available.
3. Enable **Show sensitive keys** only if you want to view the OA3 and decoded product keys. A confirmation dialog is shown before revealing them.
4. Click **Get License Info** to gather data. The progress ring indicates activity.
5. Review the populated fields. Retrieval sources describe how each value was collected.
6. Use **Export to JSON** to save the displayed data or **Copy to Clipboard** to copy a formatted summary. Both actions ask for confirmation when sensitive data is present.

## Privacy and security

- The application reads data only; it does not modify registry entries, WMI classes, or activation state.
- No activation bypassing or patching is performed.
- Sensitive keys remain hidden unless the user explicitly opts in and confirms.

## Project structure

```
Intelicense/
├── App.xaml / App.xaml.cs          # Application bootstrap
├── MainWindow.xaml(.cs)            # Main UI with bindings to the view model
├── Models/WindowsLicenseInfo.cs    # Data model with observable properties
├── ViewModels/MainViewModel.cs     # MVVM logic and commands
├── Services/                       # Data retrieval, dialogs, file and clipboard services
├── Converters/BooleanToVisibilityConverter.cs
└── README.md
```

## License

This project is provided for demonstration purposes. Refer to `LICENSE.txt` for license details.
