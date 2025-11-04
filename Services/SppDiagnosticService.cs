using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using Intelicense.Models;
using Microsoft.Win32;

namespace Intelicense.Services;

public static class SppDiagnosticService
{
    private static readonly Guid WindowsApplicationId = new("55C92734-D682-4D71-983E-D6EC3F16059F");
    private static readonly Guid Office15ApplicationId = new("0FF1CE15-A989-479D-AF46-F275C6370663");
    private static readonly Guid Office14ApplicationId = new("59A52881-A989-479D-AF46-F275C6370663");

    private static readonly IReadOnlyDictionary<uint, string> ProductTypeDescriptions = new Dictionary<uint, string>
    {
        { 0x00000006, "Business" },
        { 0x00000010, "Home" },
        { 0x00000012, "Professional" },
        { 0x00000027, "Enterprise" },
        { 0x0000002A, "Enterprise N" },
        { 0x00000030, "Education" },
        { 0x0000003C, "Enterprise S" },
        { 0x0000003F, "Professional Education" },
        { 0x00000040, "Professional Education N" },
        { 0x00000043, "Professional Workstation" },
        { 0x00000044, "Professional Workstation N" },
        { 0x0000004B, "IoT Enterprise" },
        { 0x00000065, "Professional N" },
        { 0x00000067, "Enterprise G" },
        { 0x00000068, "Enterprise G N" },
        { 0x00000079, "Server Standard" },
        { 0x0000007D, "Server Datacenter" }
    };

    private static readonly string[] LicenseStatusTextMap =
    {
        "Unlicensed",
        "Licensed",
        "Initial grace period",
        "Additional grace period",
        "Non-genuine grace period",
        "Notification",
        "Extended grace period"
    };

    public sealed class SppDiagnosticPackage
    {
        public string? Oa3Key { get; set; }
        public string? Oa3KeyMasked { get; set; }
        public string? DecodedKey { get; set; }
        public string? PartialProductKey { get; set; }
        public int? LicenseStatusCode { get; set; }
        public string? LicenseStatusText { get; set; }
        public uint? ProductTypeCode { get; set; }
        public string? ProductTypeText { get; set; }
        public List<string> Sources { get; } = new();
        public List<string> Notes { get; } = new();
        public List<SppLicenseEntry> WindowsLicenses { get; } = new();
        public List<SppLicenseEntry> OfficeLicenses { get; } = new();
    }

    public static Task<SppDiagnosticPackage> CollectAsync(bool allowSensitiveData, bool allowPowerShellFallback)
    {
        return Task.Run(() => CollectInternal(allowSensitiveData, allowPowerShellFallback));
    }

    private static SppDiagnosticPackage CollectInternal(bool allowSensitiveData, bool allowPowerShellFallback)
    {
        var package = new SppDiagnosticPackage();

        CollectFirmwareMsdm(package, allowSensitiveData);
        CollectRegistryCurrentVersion(package);
        CollectSoftwareProtectionPlatform(package, allowSensitiveData);
        CollectSoftwareLicensingProduct(package);
        CollectSoftwareLicensingService(package, allowSensitiveData);
        CollectServiceStates(package);
        CollectSlApiData(package, allowSensitiveData);
        CollectProductInfo(package);
        CollectSppLicenseEntries(package, allowSensitiveData);

        if (!allowPowerShellFallback)
        {
            AppendNote(package, "PowerShell fallback disabled by settings.");
        }

        return package;
    }

    private static void CollectFirmwareMsdm(SppDiagnosticPackage package, bool allowSensitive)
    {
        var result = FirmwareMsdmReader.TryRead();
        if (result.Found)
        {
            package.Oa3KeyMasked = MaskKey(result.Key);
            if (allowSensitive)
            {
                package.Oa3Key = result.Key;
            }
            else
            {
                AppendNote(package, "OA3 key hidden because sensitive data export is disabled.");
            }

            AddSource(package, "ACPI:MSDM");
        }
        else
        {
            var suffix = string.IsNullOrWhiteSpace(result.Error) ? "NotFound" : $"Error:{result.Error}";
            AddSource(package, $"ACPI:MSDM:{suffix}");
            if (!string.IsNullOrWhiteSpace(result.Error))
            {
                AppendNote(package, $"Firmware MSDM read error: {result.Error}");
            }
        }
    }

    private static void CollectRegistryCurrentVersion(SppDiagnosticPackage package)
    {
        const string source = "Registry:CurrentVersion";
        try
        {
            using var baseKey = OpenLocalMachineView();
            using var key = baseKey.OpenSubKey(@"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
            if (key is null)
            {
                AddSource(package, $"{source}:NotFound");
                AppendNote(package, "Registry CurrentVersion key not found.");
                return;
            }

            AddSource(package, source);
        }
        catch (Exception ex)
        {
            AddSource(package, $"{source}:Error");
            AppendNote(package, $"CurrentVersion registry read failed: {ex.Message}");
        }
    }

    private static void CollectSoftwareProtectionPlatform(SppDiagnosticPackage package, bool allowSensitive)
    {
        const string source = "Registry:SoftwareProtectionPlatform";
        try
        {
            using var baseKey = OpenLocalMachineView();
            using var key = baseKey.OpenSubKey(@"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform");
            if (key is null)
            {
                AddSource(package, $"{source}:NotFound");
                AppendNote(package, "SoftwareProtectionPlatform registry branch not found.");
                return;
            }

            if (allowSensitive && key.GetValue("DigitalProductId") is byte[] digitalProductId)
            {
                var decoded = DecodeProductKey(digitalProductId);
                if (!string.IsNullOrWhiteSpace(decoded))
                {
                    package.DecodedKey = decoded;
                }
            }
            else if (!allowSensitive)
            {
                AppendNote(package, "Registry digital product key available but hidden.");
            }

            if (key.GetValue("PartialProductKey") is string partial && !string.IsNullOrWhiteSpace(partial))
            {
                package.PartialProductKey = partial;
            }

            AddSource(package, source);
        }
        catch (Exception ex)
        {
            AddSource(package, $"{source}:Error");
            AppendNote(package, $"SoftwareProtectionPlatform registry read failed: {ex.Message}");
        }
    }

    private static void CollectSoftwareLicensingProduct(SppDiagnosticPackage package)
    {
        const string source = "WMI:SoftwareLicensingProduct";
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT PartialProductKey, LicenseStatus FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                if (obj["PartialProductKey"] is string partial)
                {
                    package.PartialProductKey = partial;
                }

                var statusValue = obj["LicenseStatus"];
                if (statusValue is not null && int.TryParse(statusValue.ToString(), out var status))
                {
                    package.LicenseStatusCode = status;
                    package.LicenseStatusText = MapLicenseStatus(status);
                }

                break;
            }

            AddSource(package, source);
        }
        catch (Exception ex)
        {
            AddSource(package, $"{source}:Error");
            AppendNote(package, $"SoftwareLicensingProduct query failed: {ex.Message}");
        }
    }

    private static void CollectSoftwareLicensingService(SppDiagnosticPackage package, bool allowSensitive)
    {
        const string source = "WMI:SoftwareLicensingService";
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM SoftwareLicensingService");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                if (obj.Properties.Cast<PropertyData>().Any())
                {
                    ExtractServiceProperty(package, obj, "TrustedTime", value =>
                    {
                        var dt = ManagementDateTimeConverter.ToDateTime(value.ToString());
                        AppendNote(package, $"TrustedTime: {dt.ToLocalTime():u}");
                    });

                    ExtractServiceProperty(package, obj, "EvaluationEndDate", value =>
                    {
                        var dt = ManagementDateTimeConverter.ToDateTime(value.ToString());
                        AppendNote(package, $"Evaluation ends: {dt.ToLocalTime():u}");
                    });

                    ExtractServiceProperty(package, obj, "RemainingReArmCount", value =>
                    {
                        AppendNote(package, $"Remaining rearm count: {value}");
                    });

                    ExtractServiceProperty(package, obj, "RemainingSkuReArmCount", value =>
                    {
                        AppendNote(package, $"Remaining SKU rearm count: {value}");
                    });

                    ExtractServiceProperty(package, obj, "RemainingAppReArmCount", value =>
                    {
                        AppendNote(package, $"Remaining app rearm count: {value}");
                    });

                    ExtractServiceProperty(package, obj, "OfflineInstallationId", value =>
                    {
                        if (allowSensitive)
                        {
                            AppendNote(package, $"Offline Installation ID: {value}");
                        }
                        else
                        {
                            AppendNote(package, "Offline Installation ID available (hidden).");
                        }
                    });

                    ExtractServiceProperty(package, obj, "UXDifferentiator", value =>
                    {
                        AppendNote(package, $"UX Differentiator: {value}");
                    });
                }

                break;
            }

            AddSource(package, source);
        }
        catch (Exception ex)
        {
            AddSource(package, $"{source}:Error");
            AppendNote(package, $"SoftwareLicensingService query failed: {ex.Message}");
        }
    }

    private static void CollectServiceStates(SppDiagnosticPackage package)
    {
        QueryService(package, "sppsvc");
        QueryService(package, "osppsvc");
    }

    private static void CollectSlApiData(SppDiagnosticPackage package, bool allowSensitive)
    {
        var serviceInfo = SppManagerInterop.TryGetServiceInformation("Version");
        if (serviceInfo.Success && serviceInfo.HasString)
        {
            AddSource(package, "SL:SLGetServiceInformation:Version");
            AppendNote(package, $"SL service version: {serviceInfo.StringValue}");
        }
        else if (!serviceInfo.Success && !string.IsNullOrWhiteSpace(serviceInfo.ErrorMessage))
        {
            AddSource(package, "SL:SLGetServiceInformation:Error");
            AppendNote(package, $"SL service info error: {serviceInfo.ErrorMessage}");
        }

        var windowsInfoKeys = new Dictionary<string, bool>
        {
            { "OfflineInstallationId", allowSensitive },
            { "TrustedTime", true },
            { "EvaluationEndDate", true },
            { "UXDifferentiator", true }
        };

        foreach (var kvp in windowsInfoKeys)
        {
            var result = SppManagerInterop.TryGetWindowsInformationString(kvp.Key);
            if (result.Success && result.HasString)
            {
                AddSource(package, $"SL:SLGetWindowsInformation:{kvp.Key}");
                if (kvp.Value)
                {
                    AppendNote(package, $"SL {kvp.Key}: {result.StringValue}");
                }
                else
                {
                    AppendNote(package, $"SL {kvp.Key}: value hidden (sensitive).");
                }
            }
            else if (!result.Success && !string.IsNullOrWhiteSpace(result.ErrorMessage))
            {
                AddSource(package, $"SL:SLGetWindowsInformation:{kvp.Key}:Error");
                AppendNote(package, $"SL {kvp.Key} error: {result.ErrorMessage}");
            }
        }

        var remainingRearm = SppManagerInterop.TryGetWindowsInformationDword("RemainingRearmCount");
        if (remainingRearm.Success && remainingRearm.DwordValue.HasValue)
        {
            AddSource(package, "SL:SLGetWindowsInformationDWORD:RemainingRearmCount");
            AppendNote(package, $"SL Remaining rearm count: {remainingRearm.DwordValue.Value}");
        }
        else if (!remainingRearm.Success && !string.IsNullOrWhiteSpace(remainingRearm.ErrorMessage))
        {
            AddSource(package, "SL:SLGetWindowsInformationDWORD:RemainingRearmCount:Error");
            AppendNote(package, $"SL RemainingRearmCount error: {remainingRearm.ErrorMessage}");
        }

        var licensingStatus = SppManagerInterop.TryGetLicensingStatusInformation(null, null);
        if (licensingStatus.Success)
        {
            AddSource(package, "SL:SLGetLicensingStatusInformation");
            var first = licensingStatus.Entries.FirstOrDefault();
            if (first != default)
            {
                var statusValue = (int)first.Status;
                package.LicenseStatusCode ??= statusValue;
                package.LicenseStatusText ??= MapLicenseStatus(statusValue);
            }
        }
        else if (!string.IsNullOrWhiteSpace(licensingStatus.ErrorMessage))
        {
            AddSource(package, "SL:SLGetLicensingStatusInformation:Error");
            AppendNote(package, $"SL licensing status error: {licensingStatus.ErrorMessage}");
        }

        var genuine = SppManagerInterop.TryIsWindowsGenuineLocal();
        if (genuine.Success && genuine.State.HasValue)
        {
            AddSource(package, "SL:SLIsWindowsGenuineLocal");
            AppendNote(package, $"SL genuine state: {genuine.State.Value}");
        }
        else if (!genuine.Success && !string.IsNullOrWhiteSpace(genuine.ErrorMessage))
        {
            AddSource(package, "SL:SLIsWindowsGenuineLocal:Error");
            AppendNote(package, $"SL genuine check error: {genuine.ErrorMessage}");
        }
    }

    private static void CollectProductInfo(SppDiagnosticPackage package)
    {
        try
        {
            var version = Environment.OSVersion.Version;
            if (GetProductInfo(version.Major, version.Minor, 0, 0, out var productType))
            {
                package.ProductTypeCode = productType;
                package.ProductTypeText = ProductTypeDescriptions.TryGetValue(productType, out var text) ? text : "Unknown";
                AddSource(package, "Win32API:GetProductInfo");
            }
            else
            {
                AppendNote(package, "GetProductInfo failed.");
                AddSource(package, "Win32API:GetProductInfo:Error");
            }
        }
        catch (Exception ex)
        {
            AddSource(package, "Win32API:GetProductInfo:Error");
            AppendNote(package, $"GetProductInfo exception: {ex.Message}");
        }
    }

    private static void CollectSppLicenseEntries(SppDiagnosticPackage package, bool allowSensitive)
    {
        CollectLicensesForApplication(package, allowSensitive, WindowsApplicationId, package.WindowsLicenses, "Windows");

        var officeCountBefore = package.OfficeLicenses.Count;
        CollectLicensesForApplication(package, allowSensitive, Office15ApplicationId, package.OfficeLicenses, "Office15");
        CollectLicensesForApplication(package, allowSensitive, Office14ApplicationId, package.OfficeLicenses, "Office14");

        if (package.OfficeLicenses.Count == officeCountBefore)
        {
            AppendNote(package, "No Office licenses were returned by the Software Protection Platform APIs.");
        }

        if (package.WindowsLicenses.Count == 0)
        {
            AppendNote(package, "No Windows licenses were returned by the Software Protection Platform APIs.");
        }
    }

    private static void CollectLicensesForApplication(
        SppDiagnosticPackage package,
        bool allowSensitive,
        Guid applicationId,
        List<SppLicenseEntry> target,
        string tag)
    {
        var listResult = SppManagerInterop.TryGetSlidList(SppManagerInterop.SlidType.Application, applicationId, SppManagerInterop.SlidType.ProductSku);
        if (!listResult.Success)
        {
            AddSource(package, $"SL:SLGetSLIDList:{tag}:Error");
            if (!string.IsNullOrWhiteSpace(listResult.ErrorMessage))
            {
                AppendNote(package, $"SLGetSLIDList for {tag} failed: {listResult.ErrorMessage}");
            }
            return;
        }

        if (listResult.Ids.Count == 0)
        {
            return;
        }

        AddSource(package, $"SL:SLGetSLIDList:{tag}");

        var statusResult = SppManagerInterop.TryGetLicensingStatusInformation(applicationId, null);
        var statusMap = new Dictionary<Guid, SppManagerInterop.SlLicensingStatusEntry>();
        if (statusResult.Success)
        {
            foreach (var statusEntry in statusResult.Entries)
            {
                statusMap[statusEntry.SkuId] = statusEntry;
            }

            if (statusResult.Entries.Count > 0)
            {
                AddSource(package, $"SL:SLGetLicensingStatusInformation:{tag}");
            }
        }
        else if (!string.IsNullOrWhiteSpace(statusResult.ErrorMessage))
        {
            AddSource(package, $"SL:SLGetLicensingStatusInformation:{tag}:Error");
            AppendNote(package, $"SL licensing status for {tag} failed: {statusResult.ErrorMessage}");
        }

        int initialCount = target.Count;
        foreach (var skuId in listResult.Ids)
        {
            var licenseEntry = BuildSppLicenseEntry(allowSensitive, skuId, statusMap, tag);
            if (licenseEntry is not null)
            {
                target.Add(licenseEntry);
            }
        }

        if (target.Count == initialCount)
        {
            AppendNote(package, $"No {tag} licenses contained retrievable product key information.");
        }
    }

    private static SppLicenseEntry? BuildSppLicenseEntry(
        bool allowSensitive,
        Guid skuId,
        IReadOnlyDictionary<Guid, SppManagerInterop.SlLicensingStatusEntry> statusMap,
        string tag)
    {
        var entry = new SppLicenseEntry
        {
            ActivationId = skuId
        };

        var nameResult = SppManagerInterop.TryGetProductSkuInformation(skuId, "Name");
        if (nameResult.Success && nameResult.HasString)
        {
            entry.Name = nameResult.StringValue;
        }
        else if (!nameResult.Success && !string.IsNullOrWhiteSpace(nameResult.ErrorMessage))
        {
            entry.Notes.Add($"Name unavailable ({nameResult.ErrorMessage}).");
        }

        var descriptionResult = SppManagerInterop.TryGetProductSkuInformation(skuId, "Description");
        if (descriptionResult.Success && descriptionResult.HasString)
        {
            entry.Description = descriptionResult.StringValue;
        }
        else if (!descriptionResult.Success && !string.IsNullOrWhiteSpace(descriptionResult.ErrorMessage))
        {
            entry.Notes.Add($"Description unavailable ({descriptionResult.ErrorMessage}).");
        }

        var dependsResult = SppManagerInterop.TryGetProductSkuInformation(skuId, "DependsOn");
        if (dependsResult.Success && dependsResult.HasString)
        {
            entry.IsAddon = !string.IsNullOrWhiteSpace(dependsResult.StringValue);
        }

        var phoneResult = SppManagerInterop.TryGetProductSkuInformation(skuId, "msft:sl/EUL/PHONE/PUBLIC");
        if (phoneResult.Success)
        {
            entry.PhoneActivationAvailable = !string.IsNullOrWhiteSpace(phoneResult.StringValue);
        }
        else if (!string.IsNullOrWhiteSpace(phoneResult.ErrorMessage))
        {
            entry.Notes.Add($"Phone activation query failed ({phoneResult.ErrorMessage}).");
        }

        Guid? productKeyId = null;
        var pkeyResult = SppManagerInterop.TryGetProductSkuInformation(skuId, "PKeyId");
        if (pkeyResult.Success && pkeyResult.HasString && Guid.TryParse(pkeyResult.StringValue, out var parsed))
        {
            productKeyId = parsed;
        }
        else if (!pkeyResult.Success && !string.IsNullOrWhiteSpace(pkeyResult.ErrorMessage))
        {
            entry.Notes.Add($"Product key identifier unavailable ({pkeyResult.ErrorMessage}).");
        }

        if (productKeyId.HasValue)
        {
            var partialResult = SppManagerInterop.TryGetPKeyInformation(productKeyId.Value, "PartialProductKey");
            if (partialResult.Success && partialResult.HasString)
            {
                entry.PartialProductKey = partialResult.StringValue;
            }
            else if (!partialResult.Success && !string.IsNullOrWhiteSpace(partialResult.ErrorMessage))
            {
                entry.Notes.Add($"Partial product key unavailable ({partialResult.ErrorMessage}).");
            }

            var channelResult = SppManagerInterop.TryGetPKeyInformation(productKeyId.Value, "Channel");
            if (channelResult.Success && channelResult.HasString)
            {
                entry.ProductKeyChannel = channelResult.StringValue;
            }
            else if (!channelResult.Success && !string.IsNullOrWhiteSpace(channelResult.ErrorMessage))
            {
                entry.Notes.Add($"Product key channel unavailable ({channelResult.ErrorMessage}).");
            }

            if (allowSensitive)
            {
                var extendedResult = SppManagerInterop.TryGetPKeyInformation(productKeyId.Value, "DigitalPID");
                if (extendedResult.Success && extendedResult.HasString)
                {
                    entry.ExtendedProductId = extendedResult.StringValue;
                }
                else if (!extendedResult.Success && !string.IsNullOrWhiteSpace(extendedResult.ErrorMessage))
                {
                    entry.Notes.Add($"Extended PID unavailable ({extendedResult.ErrorMessage}).");
                }

                var productIdResult = SppManagerInterop.TryGetPKeyInformation(productKeyId.Value, "DigitalPID2");
                if (productIdResult.Success && productIdResult.HasString)
                {
                    entry.ProductId = productIdResult.StringValue;
                }
                else if (!productIdResult.Success && !string.IsNullOrWhiteSpace(productIdResult.ErrorMessage))
                {
                    entry.Notes.Add($"Product ID unavailable ({productIdResult.ErrorMessage}).");
                }
            }
            else
            {
                entry.Notes.Add("Extended and product identifiers are hidden because sensitive data export is disabled.");
            }
        }

        if (allowSensitive)
        {
            var iidResult = SppManagerInterop.TryGenerateOfflineInstallationId(skuId);
            if (iidResult.Success && iidResult.HasString)
            {
                entry.OfflineInstallationId = iidResult.StringValue;
            }
            else if (!iidResult.Success && !string.IsNullOrWhiteSpace(iidResult.ErrorMessage))
            {
                entry.Notes.Add($"Installation ID unavailable ({iidResult.ErrorMessage}).");
            }
        }
        else
        {
            entry.Notes.Add("Installation ID generation skipped because sensitive data export is disabled.");
        }

        if (statusMap.TryGetValue(skuId, out var statusEntry))
        {
            PopulateStatus(entry, statusEntry);
        }
        else if (statusMap.Count > 0)
        {
            entry.LicenseStatus = "Unknown";
            entry.Notes.Add("No licensing status entry was returned for this activation identifier.");
        }

        if (string.IsNullOrWhiteSpace(entry.Name) && string.IsNullOrWhiteSpace(entry.Description))
        {
            entry.Name = $"{tag} license {skuId}";
        }

        return entry;
    }

    private static void PopulateStatus(SppLicenseEntry entry, SppManagerInterop.SlLicensingStatusEntry statusEntry)
    {
        entry.LicenseStatusCode = (int)statusEntry.Status;
        entry.ReasonHResult = statusEntry.ReasonHResult;
        entry.GraceTimeMinutes = statusEntry.GraceTimeMinutes;

        if (statusEntry.GraceTimeMinutes > 0)
        {
            entry.GraceTimeDays = (uint)Math.Max(0, Math.Round(statusEntry.GraceTimeMinutes / 1440d, MidpointRounding.AwayFromZero));
            entry.GraceExpiry = DateTimeOffset.Now.AddMinutes(statusEntry.GraceTimeMinutes);
        }

        if (statusEntry.ValidityExpiration > 0 && statusEntry.ValidityExpiration < ulong.MaxValue)
        {
            try
            {
                entry.EvaluationExpiryUtc = DateTimeOffset.FromFileTime((long)statusEntry.ValidityExpiration);
                entry.Notes.Add($"Evaluation end date: {entry.EvaluationExpiryUtc:yyyy-MM-dd HH:mm:ss} UTC.");
            }
            catch (ArgumentOutOfRangeException)
            {
                entry.Notes.Add($"Evaluation end date returned unexpected value ({statusEntry.ValidityExpiration}).");
            }
        }

        int normalized = NormalizeStatus((int)statusEntry.Status, statusEntry.ReasonHResult);
        entry.NormalizedStatusCode = normalized;

        entry.LicenseStatus = normalized switch
        {
            0 => "Unlicensed",
            1 => "Licensed",
            2 => "Initial grace period",
            3 => "Additional grace period",
            4 => "Non-genuine grace period",
            5 => "Notification",
            6 => "Extended grace period",
            _ => $"Unknown ({statusEntry.Status})",
        };

        if (statusEntry.GraceTimeMinutes > 0)
        {
            var days = entry.GraceTimeDays ?? 0;
            var graceText = $"{statusEntry.GraceTimeMinutes} minute(s) ({days} day(s))";
            entry.LicenseMessage = normalized == 1
                ? $"Activation expiration: {graceText}"
                : $"Time remaining: {graceText}";

            if (entry.GraceExpiry.HasValue)
            {
                entry.Notes.Add($"Grace period ends {entry.GraceExpiry:yyyy-MM-dd HH:mm:ss zzz}.");
            }
        }

        if (normalized == 5 && statusEntry.ReasonHResult != 0)
        {
            entry.Notes.Add($"Notification reason: {FormatHResult(statusEntry.ReasonHResult)}.");
            switch (statusEntry.ReasonHResult)
            {
                case unchecked((int)0xC004F00F):
                    entry.Notes.Add("KMS license expired or hardware out of tolerance.");
                    break;
                case unchecked((int)0xC004F200):
                    entry.Notes.Add("License reported as non-genuine.");
                    break;
                case unchecked((int)0xC004F009):
                case unchecked((int)0xC004F064):
                    entry.Notes.Add("Grace time expired.");
                    break;
            }
        }
        else if (normalized == 4 && statusEntry.ReasonHResult != 0)
        {
            entry.Notes.Add($"Non-genuine reason: {FormatHResult(statusEntry.ReasonHResult)}.");
        }
    }

    private static int NormalizeStatus(int status, int reason)
    {
        return status switch
        {
            2 when reason == 0x4004F00D => 3,
            2 when reason == 0x4004F065 => 4,
            2 when reason == 0x4004FC06 => 6,
            3 => 5,
            _ => status,
        };
    }

    private static string FormatHResult(int value) => $"0x{value:X8}";

    private static void QueryService(SppDiagnosticPackage package, string serviceName)
    {
        try
        {
            using var controller = new ServiceController(serviceName);
            var status = controller.Status;
            AddSource(package, $"Service:{serviceName}");
            AppendNote(package, $"Service {serviceName} status: {status}");
        }
        catch (InvalidOperationException ex)
        {
            AddSource(package, $"Service:{serviceName}:Error");
            AppendNote(package, $"Service {serviceName} query failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            AddSource(package, $"Service:{serviceName}:Error");
            AppendNote(package, $"Service {serviceName} exception: {ex.Message}");
        }
    }

    private static RegistryKey OpenLocalMachineView()
    {
        try
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        }
        catch
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
        }
    }

    private static void ExtractServiceProperty(SppDiagnosticPackage package, ManagementObject obj, string property, Action<object> handler)
    {
        var propertyData = obj.Properties
            .Cast<PropertyData>()
            .FirstOrDefault(p => string.Equals(p.Name, property, StringComparison.Ordinal));

        if (propertyData?.Value is not { } value)
        {
            return;
        }

        try
        {
            handler(value);
        }
        catch (FormatException ex)
        {
            AppendNote(package, $"Property {property} parse error: {ex.Message}");
        }
        catch (Exception ex)
        {
            AppendNote(package, $"Property {property} handler error: {ex.Message}");
        }
    }

    private static string MapLicenseStatus(int status)
    {
        if (status >= 0 && status < LicenseStatusTextMap.Length)
        {
            return LicenseStatusTextMap[status];
        }

        return $"Unknown ({status})";
    }

    private static string? DecodeProductKey(byte[] digitalProductId)
    {
        if (digitalProductId.Length < 67)
        {
            return null;
        }

        const string chars = "BCDFGHJKMPQRTVWXY2346789";
        const int keyLength = 25;
        const int keyOffset = 52;
        var keyBytes = new byte[15];
        Array.Copy(digitalProductId, keyOffset, keyBytes, 0, keyBytes.Length);

        var result = new char[keyLength];
        for (var i = keyLength - 1; i >= 0; i--)
        {
            int current = 0;
            for (var j = keyBytes.Length - 1; j >= 0; j--)
            {
                current <<= 8;
                current += keyBytes[j];
                keyBytes[j] = (byte)(current / chars.Length);
                current %= chars.Length;
            }

            result[i] = chars[current];
        }

        var builder = new StringBuilder();
        for (var i = 0; i < result.Length; i++)
        {
            if (i > 0 && i % 5 == 0)
            {
                builder.Append('-');
            }

            builder.Append(result[i]);
        }

        return builder.ToString();
    }

    private static string MaskKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        var parts = key.Split('-');
        if (parts.Length != 5)
        {
            return key;
        }

        return $"{parts[0]}-*****-*****-*****-{parts[4]}";
    }

    private static void AddSource(SppDiagnosticPackage package, string source)
    {
        if (!package.Sources.Contains(source, StringComparer.OrdinalIgnoreCase))
        {
            package.Sources.Add(source);
        }
    }

    private static void AppendNote(SppDiagnosticPackage package, string? note)
    {
        if (!string.IsNullOrWhiteSpace(note))
        {
            package.Notes.Add(note);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProductInfo(int osMajor, int osMinor, int spMajor, int spMinor, out uint productType);
}
