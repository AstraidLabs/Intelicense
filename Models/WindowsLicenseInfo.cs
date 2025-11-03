using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using System.Text.Json.Serialization;

namespace Intelicense.Models;

public partial class WindowsLicenseInfo : ObservableObject
{
    [ObservableProperty]
    private string? productName;

    [ObservableProperty]
    private string? editionId;

    [ObservableProperty]
    private string? productId;

    [ObservableProperty]
    private string? currentBuild;

    [ObservableProperty]
    private string? installationType;

    [ObservableProperty]
    private string? partialProductKey;

    [ObservableProperty]
    private string? oa3MsdmKey;

    [ObservableProperty]
    private string? oa3MsdmKeyMasked;

    [ObservableProperty]
    private string? oa3MsdmRawDumpBase64;

    [ObservableProperty]
    private string? oa3OriginalProductKey;

    [ObservableProperty]
    private string? decodedProductKey;

    [ObservableProperty]
    private uint? productTypeCode;

    [ObservableProperty]
    private string? mappedProductType;

    [ObservableProperty]
    private string? licenseStatus;

    public List<string> RetrievalSources { get; } = new();

    [JsonIgnore]
    public bool ContainsSensitiveData
    {
        get
        {
            static bool HasValue(string? value) => !string.IsNullOrWhiteSpace(value) && !value.StartsWith("Hidden", StringComparison.OrdinalIgnoreCase);
            return HasValue(Oa3MsdmKey) || HasValue(Oa3OriginalProductKey) || HasValue(DecodedProductKey);
        }
    }

    [JsonIgnore]
    public string Oa3MsdmDisplayKey => !string.IsNullOrWhiteSpace(Oa3MsdmKey) ? Oa3MsdmKey! : Oa3MsdmKeyMasked ?? string.Empty;

    public void Reset()
    {
        ProductName = string.Empty;
        EditionId = string.Empty;
        ProductId = string.Empty;
        CurrentBuild = string.Empty;
        InstallationType = string.Empty;
        PartialProductKey = string.Empty;
        Oa3MsdmKey = string.Empty;
        Oa3MsdmKeyMasked = string.Empty;
        Oa3MsdmRawDumpBase64 = string.Empty;
        Oa3OriginalProductKey = string.Empty;
        DecodedProductKey = string.Empty;
        ProductTypeCode = null;
        MappedProductType = string.Empty;
        LicenseStatus = string.Empty;
        RetrievalSources.Clear();
    }

    partial void OnOa3MsdmKeyChanged(string? value) => OnPropertyChanged(nameof(Oa3MsdmDisplayKey));

    partial void OnOa3MsdmKeyMaskedChanged(string? value) => OnPropertyChanged(nameof(Oa3MsdmDisplayKey));
}
