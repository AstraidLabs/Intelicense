using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Intelicense.Models;
using Microsoft.Win32;

namespace Intelicense.Services;

public sealed class WindowsLicenseService : IWindowsLicenseService
{
    private static readonly Dictionary<uint, string> ProductMap = new()
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

    public async Task<WindowsLicenseInfo> GatherLicenseInfoAsync(bool includeSensitive, bool usePowerShellFallback, CancellationToken cancellationToken)
    {
        var info = new WindowsLicenseInfo();
        info.Reset();

        CollectCurrentVersion(info);
        CollectFirmwareMsdm(info, includeSensitive);
        CollectSoftwareProtectionPlatform(info, includeSensitive);
        CollectSoftwareLicensingProduct(info);
        CollectSoftwareLicensingService(info);
        CollectProductInfo(info);

        if (usePowerShellFallback)
        {
            await TryPowerShellFallbackAsync(info, includeSensitive, cancellationToken).ConfigureAwait(false);
        }

        return info;
    }

    private static void CollectCurrentVersion(WindowsLicenseInfo info)
    {
        const string source = "Registry:CurrentVersion";
        try
        {
            using var baseKey = OpenLocalMachineView();
            using var key = baseKey.OpenSubKey(@"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
            if (key is null)
            {
                AddSource(info, source + " - ERROR: Not found");
                return;
            }

            info.ProductName = key.GetValue("ProductName") as string ?? info.ProductName;
            info.EditionId = key.GetValue("EditionID") as string ?? info.EditionId;
            info.ProductId = key.GetValue("ProductId") as string ?? info.ProductId;
            info.CurrentBuild = key.GetValue("BuildLabEx") as string ?? key.GetValue("CurrentBuild") as string ?? info.CurrentBuild;
            info.InstallationType = key.GetValue("InstallationType") as string ?? info.InstallationType;

            AddSource(info, source);
        }
        catch (UnauthorizedAccessException)
        {
            AddSource(info, source + " - ERROR: Access denied");
        }
        catch (Exception ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
    }

    private static void CollectFirmwareMsdm(WindowsLicenseInfo info, bool includeSensitive)
    {
        const string source = "ACPI:MSDM";
        var msdm = FirmwareMsdmReader.TryRead();

        if (msdm.Found)
        {
            info.Oa3MsdmRawDumpBase64 = includeSensitive ? msdm.RawBase64 : string.Empty;
            info.Oa3MsdmKeyMasked = Mask(msdm.Key);

            if (includeSensitive)
            {
                info.Oa3MsdmKey = msdm.Key;
            }
            else
            {
                info.Oa3MsdmKey = null;
            }

            AddSource(info, source);
            return;
        }

        info.Oa3MsdmRawDumpBase64 = string.Empty;
        info.Oa3MsdmKeyMasked = string.Empty;
        info.Oa3MsdmKey = includeSensitive ? string.Empty : null;

        var suffix = string.IsNullOrWhiteSpace(msdm.Error) ? "NotFound" : $"Error:{msdm.Error}";
        AddSource(info, $"{source}:{suffix}");
    }

    private static void CollectSoftwareProtectionPlatform(WindowsLicenseInfo info, bool includeSensitive)
    {
        const string source = "Registry:SoftwareProtectionPlatform";
        try
        {
            using var baseKey = OpenLocalMachineView();
            using var key = baseKey.OpenSubKey(@"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform");
            if (key is null)
            {
                AddSource(info, source + " - ERROR: Not found");
                if (!includeSensitive)
                {
                    info.Oa3OriginalProductKey = "Hidden (confirmation required)";
                    info.DecodedProductKey = "Hidden (confirmation required)";
                }
                return;
            }

            if (includeSensitive)
            {
                var oa3 = key.GetValue("OA3xOriginalProductKey") as string;
                info.Oa3OriginalProductKey = string.IsNullOrWhiteSpace(oa3) ? info.Oa3OriginalProductKey : oa3;

                if (key.GetValue("DigitalProductId") is byte[] digitalProductId)
                {
                    info.DecodedProductKey = DecodeProductKey(digitalProductId) ?? info.DecodedProductKey;
                }
            }
            else
            {
                info.Oa3OriginalProductKey = "Hidden (confirmation required)";
                info.DecodedProductKey = "Hidden (confirmation required)";
            }

            AddSource(info, source);
        }
        catch (UnauthorizedAccessException)
        {
            AddSource(info, source + " - ERROR: Access denied");
        }
        catch (Exception ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
            if (!includeSensitive)
            {
                info.Oa3OriginalProductKey = "Hidden (confirmation required)";
                info.DecodedProductKey = "Hidden (confirmation required)";
            }
        }
    }

    private static string Mask(string? key)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length < 29)
        {
            return key ?? string.Empty;
        }

        var parts = key.Split('-');
        if (parts.Length != 5)
        {
            return key;
        }

        return $"{parts[0]}-*****-*****-*****-{parts[4]}";
    }

    private static void CollectSoftwareLicensingProduct(WindowsLicenseInfo info)
    {
        const string source = "WMI:SoftwareLicensingProduct";
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT PartialProductKey, LicenseStatus FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL");
            foreach (var obj in searcher.Get().Cast<ManagementObject>())
            {
                info.PartialProductKey = obj["PartialProductKey"]?.ToString();
                info.LicenseStatus = MapLicenseStatus(obj["LicenseStatus"]);
                break;
            }

            AddSource(info, source);
        }
        catch (UnauthorizedAccessException)
        {
            AddSource(info, source + " - ERROR: Access denied");
        }
        catch (ManagementException ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
        catch (Exception ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
    }

    private static void CollectSoftwareLicensingService(WindowsLicenseInfo info)
    {
        const string source = "WMI:SoftwareLicensingService";
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Version FROM SoftwareLicensingService");
            foreach (var _ in searcher.Get())
            {
                AddSource(info, source);
                return;
            }

            AddSource(info, source + " - ERROR: Not available");
        }
        catch (UnauthorizedAccessException)
        {
            AddSource(info, source + " - ERROR: Access denied");
        }
        catch (ManagementException ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
        catch (Exception ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
    }

    private static void CollectProductInfo(WindowsLicenseInfo info)
    {
        const string source = "Win32API:GetProductInfo";
        try
        {
            var version = Environment.OSVersion.Version;
            if (GetProductInfo(version.Major, version.Minor, 0, 0, out var productType))
            {
                info.ProductTypeCode = productType;
                if (ProductMap.TryGetValue(productType, out var mapped))
                {
                    info.MappedProductType = mapped;
                }
                else
                {
                    info.MappedProductType = "Unknown";
                }

                AddSource(info, source);
            }
            else
            {
                var error = Marshal.GetLastWin32Error();
                AddSource(info, source + $" - ERROR: {error}");
            }
        }
        catch (Exception ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
    }

    private static RegistryKey OpenLocalMachineView()
    {
        try
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        }
        catch (IOException)
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
        }
    }

    private static void AddSource(WindowsLicenseInfo info, string source)
    {
        if (!info.RetrievalSources.Contains(source, StringComparer.OrdinalIgnoreCase))
        {
            info.RetrievalSources.Add(source);
        }
    }

    private static string MapLicenseStatus(object? statusValue)
    {
        if (statusValue is null)
        {
            return string.Empty;
        }

        if (!int.TryParse(statusValue.ToString(), out var status))
        {
            return statusValue.ToString() ?? string.Empty;
        }

        return status switch
        {
            0 => "Unlicensed",
            1 => "Licensed",
            2 => "OOBGrace",
            3 => "OOTGrace",
            4 => "NonGenuineGrace",
            5 => "Notification",
            6 => "ExtendedGrace",
            _ => $"Unknown ({status})"
        };
    }

    private static string? DecodeProductKey(byte[] digitalProductId)
    {
        if (digitalProductId.Length < 67)
        {
            return null;
        }

        const string keyChars = "BCDFGHJKMPQRTVWXY2346789";
        const int keyLength = 25;
        const int keyStartIndex = 52;
        var keyBytes = new byte[15];
        Array.Copy(digitalProductId, keyStartIndex, keyBytes, 0, keyBytes.Length);

        var chars = new char[keyLength];
        for (var i = keyLength - 1; i >= 0; i--)
        {
            var current = 0;
            for (var j = keyBytes.Length - 1; j >= 0; j--)
            {
                current <<= 8;
                current += keyBytes[j];
                keyBytes[j] = (byte)(current / keyChars.Length);
                current %= keyChars.Length;
            }

            chars[i] = keyChars[current];
        }

        var builder = new StringBuilder();
        for (var i = 0; i < chars.Length; i++)
        {
            if (i > 0 && i % 5 == 0)
            {
                builder.Append('-');
            }

            builder.Append(chars[i]);
        }

        return builder.ToString();
    }

    private async Task TryPowerShellFallbackAsync(WindowsLicenseInfo info, bool includeSensitive, CancellationToken cancellationToken)
    {
        const string source = "PowerShell:Fallback";
        var executable = FindPowerShellExecutable();
        if (string.IsNullOrEmpty(executable))
        {
            AddSource(info, source + " - ERROR: PowerShell not available");
            return;
        }

        var script = @"
$cv = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
$spp = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -ErrorAction SilentlyContinue
$product = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter 'PartialProductKey IS NOT NULL' | Select-Object -First 1
$result = [ordered]@{
    ProductName = $cv.ProductName
    EditionId = $cv.EditionID
    ProductId = $cv.ProductId
    CurrentBuild = $cv.BuildLabEx
    InstallationType = $cv.InstallationType
    PartialProductKey = $product.PartialProductKey
    LicenseStatus = $product.LicenseStatus
    Oa3OriginalProductKey = if ($null -ne $spp) { $spp.OA3xOriginalProductKey } else { $null }
    DecodedProductKey = $null
    ProductTypeCode = $null
}
$result | ConvertTo-Json -Depth 3 -Compress
";

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

        var startInfo = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encoded);

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                AddSource(info, source + " - ERROR: Unable to start PowerShell");
                return;
            }

            using var registration = cancellationToken.Register(() =>
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill();
                    }
                }
                catch
                {
                    // Ignore cancellation errors
                }
            });

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(process.WaitForExitAsync(cancellationToken), outputTask, errorTask).ConfigureAwait(false);

            if (process.ExitCode != 0)
            {
                var error = await errorTask.ConfigureAwait(false);
                AddSource(info, source + " - ERROR: " + error.Trim());
                return;
            }

            var output = await outputTask.ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(output))
            {
                AddSource(info, source + " - ERROR: Empty response");
                return;
            }

            using var doc = JsonDocument.Parse(output);
            var root = doc.RootElement;

            ApplyIfMissing(() => info.ProductName, v => info.ProductName = v, root, "ProductName");
            ApplyIfMissing(() => info.EditionId, v => info.EditionId = v, root, "EditionId");
            ApplyIfMissing(() => info.ProductId, v => info.ProductId = v, root, "ProductId");
            ApplyIfMissing(() => info.CurrentBuild, v => info.CurrentBuild = v, root, "CurrentBuild");
            ApplyIfMissing(() => info.InstallationType, v => info.InstallationType = v, root, "InstallationType");
            ApplyIfMissing(() => info.PartialProductKey, v => info.PartialProductKey = v, root, "PartialProductKey");

            if (string.IsNullOrWhiteSpace(info.LicenseStatus) && root.TryGetProperty("LicenseStatus", out var statusElement))
            {
                if (statusElement.ValueKind == JsonValueKind.Number && statusElement.TryGetInt32(out var statusCode))
                {
                    info.LicenseStatus = MapLicenseStatus(statusCode);
                }
                else
                {
                    info.LicenseStatus = statusElement.GetString();
                }
            }

            if (includeSensitive)
            {
                ApplyIfMissing(() => info.Oa3OriginalProductKey, v => info.Oa3OriginalProductKey = v, root, "Oa3OriginalProductKey");
            }

            AddSource(info, source);
        }
        catch (OperationCanceledException)
        {
            AddSource(info, source + " - ERROR: Cancelled");
        }
        catch (Exception ex)
        {
            AddSource(info, source + " - ERROR: " + ex.Message);
        }
    }

    private static string? FindPowerShellExecutable()
    {
        var candidates = new[] { "pwsh", "powershell" };
        foreach (var candidate in candidates)
        {
            try
            {
                var path = ResolveExecutable(candidate);
                if (!string.IsNullOrEmpty(path))
                {
                    return path;
                }
            }
            catch
            {
                // Ignore resolution issues
            }
        }

        return null;
    }

    private static string? ResolveExecutable(string name)
    {
        if (File.Exists(name))
        {
            return Path.GetFullPath(name);
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathEnv))
        {
            return null;
        }

        foreach (var path in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            var candidate = Path.Combine(path.Trim(), name + ".exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static void ApplyIfMissing(Func<string?> getter, Action<string?> setter, JsonElement root, string property)
    {
        if (!string.IsNullOrWhiteSpace(getter()))
        {
            return;
        }

        if (root.TryGetProperty(property, out var element))
        {
            setter(element.ValueKind == JsonValueKind.Null ? null : element.GetString());
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProductInfo(int dwOSMajorVersion, int dwOSMinorVersion, int dwSpMajorVersion, int dwSpMinorVersion, out uint pdwReturnedProductType);
}
