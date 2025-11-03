using System;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Intelicense.Models;
using Intelicense.Services;

namespace Intelicense.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IWindowsLicenseService _licenseService;
    private readonly IDialogService _dialogService;
    private readonly IFileService _fileService;
    private readonly IClipboardService _clipboardService;
    private CancellationTokenSource? _cancellationTokenSource;

    [ObservableProperty]
    private WindowsLicenseInfo licenseInfo = new();

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private bool usePowerShellFallback = true;

    [ObservableProperty]
    private bool showSensitiveKeys;

    [ObservableProperty]
    private string? statusMessage;

    public string RetrievalSourcesDisplay => LicenseInfo?.RetrievalSources is { Count: > 0 } sources
        ? string.Join(Environment.NewLine, sources)
        : string.Empty;

    public string ProductTypeDisplay
    {
        get
        {
            if (LicenseInfo?.ProductTypeCode is uint code)
            {
                return string.IsNullOrWhiteSpace(LicenseInfo.MappedProductType)
                    ? code.ToString()
                    : $"{code} ({LicenseInfo.MappedProductType})";
            }

            return LicenseInfo?.MappedProductType ?? string.Empty;
        }
    }

    public MainViewModel(IWindowsLicenseService licenseService, IDialogService dialogService, IFileService fileService, IClipboardService clipboardService)
    {
        _licenseService = licenseService;
        _dialogService = dialogService;
        _fileService = fileService;
        _clipboardService = clipboardService;
    }

    partial void OnLicenseInfoChanged(WindowsLicenseInfo value)
    {
        OnPropertyChanged(nameof(RetrievalSourcesDisplay));
        OnPropertyChanged(nameof(ProductTypeDisplay));
    }

    partial void OnIsBusyChanged(bool value)
    {
        GetLicenseInfoCommand.NotifyCanExecuteChanged();
        ExportToJsonCommand.NotifyCanExecuteChanged();
        CopyToClipboardCommand.NotifyCanExecuteChanged();
    }

    private bool CanExecuteOperations() => !IsBusy;

    [RelayCommand(CanExecute = nameof(CanExecuteOperations))]
    private async Task GetLicenseInfoAsync()
    {
        if (IsBusy)
        {
            return;
        }

        var includeSensitive = false;
        if (ShowSensitiveKeys)
        {
            includeSensitive = await _dialogService.ShowConfirmationAsync("Confirm sensitive data", "Sensitive license keys may be visible. Do you want to proceed?");
            if (!includeSensitive)
            {
                ShowSensitiveKeys = false;
            }
        }

        _cancellationTokenSource?.Cancel();
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();

        try
        {
            IsBusy = true;
            StatusMessage = "Collecting license information...";
            var info = await _licenseService.GatherLicenseInfoAsync(includeSensitive, UsePowerShellFallback, _cancellationTokenSource.Token);
            LicenseInfo = info;
            StatusMessage = "License information updated.";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Collection cancelled.";
        }
        catch (Exception ex)
        {
            await _dialogService.ShowMessageAsync("Error", ex.Message);
            StatusMessage = "Collection failed.";
        }
        finally
        {
            IsBusy = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }
    }

    [RelayCommand(CanExecute = nameof(CanExecuteOperations))]
    private async Task ExportToJsonAsync()
    {
        if (LicenseInfo is null)
        {
            return;
        }

        if (LicenseInfo.ContainsSensitiveData)
        {
            var confirmed = await _dialogService.ShowConfirmationAsync("Export sensitive data", "The export includes sensitive license keys. Continue?");
            if (!confirmed)
            {
                return;
            }
        }

        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(LicenseInfo, options);
        var fileName = $"LicenseInfo_{DateTime.Now:yyyyMMdd_HHmmss}";
        var saved = await _fileService.SaveJsonAsync(fileName, json);
        StatusMessage = saved ? "License data exported." : "Export cancelled.";
    }

    [RelayCommand(CanExecute = nameof(CanExecuteOperations))]
    private async Task CopyToClipboardAsync()
    {
        if (LicenseInfo is null)
        {
            return;
        }

        if (LicenseInfo.ContainsSensitiveData)
        {
            var confirmed = await _dialogService.ShowConfirmationAsync("Copy sensitive data", "Clipboard contents may include sensitive license keys. Continue?");
            if (!confirmed)
            {
                return;
            }
        }

        var builder = new StringBuilder();
        builder.AppendLine($"Product Name: {LicenseInfo.ProductName}");
        builder.AppendLine($"Edition ID: {LicenseInfo.EditionId}");
        builder.AppendLine($"Product ID: {LicenseInfo.ProductId}");
        builder.AppendLine($"Current Build: {LicenseInfo.CurrentBuild}");
        builder.AppendLine($"Installation Type: {LicenseInfo.InstallationType}");
        builder.AppendLine($"Partial Product Key: {LicenseInfo.PartialProductKey}");
        builder.AppendLine($"OA3 (MSDM) Key: {LicenseInfo.Oa3MsdmDisplayKey}");
        builder.AppendLine($"OA3 (MSDM) Raw Dump (Base64): {LicenseInfo.Oa3MsdmRawDumpBase64}");
        builder.AppendLine($"OA3 Original Product Key: {LicenseInfo.Oa3OriginalProductKey}");
        builder.AppendLine($"Decoded Product Key: {LicenseInfo.DecodedProductKey}");
        builder.AppendLine($"Product Type Code: {LicenseInfo.ProductTypeCode}");
        builder.AppendLine($"Mapped Edition: {LicenseInfo.MappedProductType}");
        builder.AppendLine($"License Status: {LicenseInfo.LicenseStatus}");
        builder.AppendLine("Retrieval Sources:");
        foreach (var source in LicenseInfo.RetrievalSources)
        {
            builder.AppendLine(" - " + source);
        }

        await _clipboardService.CopyTextAsync(builder.ToString());
        StatusMessage = "License data copied.";
    }
}
