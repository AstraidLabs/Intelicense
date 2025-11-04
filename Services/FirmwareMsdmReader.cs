using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Intelicense.Services;

public static class FirmwareMsdmReader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint provider, uint tableId, IntPtr pBuffer, uint size);

    public readonly record struct MsdmResult(bool Found, string Key, string RawBase64, string Error);

    public static MsdmResult TryRead()
    {
        try
        {
            const string providerSignature = "ACPI";
            const string tableSignature = "MSDM";
            uint provider = Sig(providerSignature);
            uint table = Sig(tableSignature);

            uint size = GetSystemFirmwareTable(provider, table, IntPtr.Zero, 0);
            if (size == 0)
            {
                return new MsdmResult(false, string.Empty, string.Empty, "MSDM table not present");
            }

            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal((int)size);
                uint read = GetSystemFirmwareTable(provider, table, buffer, size);
                if (read == 0 || read != size)
                {
                    return new MsdmResult(false, string.Empty, string.Empty, "MSDM table read failed");
                }

                byte[] data = new byte[size];
                Marshal.Copy(buffer, data, 0, (int)size);

                string? key = ExtractKey(data);
                string base64 = data.Length > 0 ? Convert.ToBase64String(data) : string.Empty;

                if (string.IsNullOrWhiteSpace(key))
                {
                    return new MsdmResult(false, string.Empty, base64, "Product key not found in MSDM payload");
                }

                return new MsdmResult(true, key, base64, string.Empty);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        catch (Exception ex)
        {
            return new MsdmResult(false, string.Empty, string.Empty, ex.Message);
        }
    }

    private static uint Sig(string signature)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(signature);
        if (bytes.Length != 4)
        {
            throw new ArgumentException("Signature must contain exactly 4 ASCII characters", nameof(signature));
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static string? ExtractKey(byte[] data)
    {
        string ascii = Encoding.ASCII.GetString(data);
        var match = Regex.Match(ascii, "[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            return match.Value.ToUpperInvariant();
        }

        var builder = new StringBuilder(data.Length);
        foreach (byte b in data)
        {
            builder.Append(b >= 32 && b <= 126 ? (char)b : ' ');
        }

        match = Regex.Match(builder.ToString(), "[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}", RegexOptions.IgnoreCase);
        return match.Success ? match.Value.ToUpperInvariant() : null;
    }
}
