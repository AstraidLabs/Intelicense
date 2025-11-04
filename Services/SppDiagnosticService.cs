using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Intelicense.Services;

public static class SppDiagnosticService
{
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
        if (!obj.Properties.Contains(property))
        {
            return;
        }

        var value = obj[property];
        if (value is null)
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
