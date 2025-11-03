using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Intelicense.Services;

public static class FirmwareMsdmReader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint provider, uint tableId, IntPtr pBuffer, uint size);

    private static uint Sig(string s)
    {
        var b = Encoding.ASCII.GetBytes(s);
        if (b.Length != 4)
        {
            throw new ArgumentException("Signature must be 4 chars", nameof(s));
        }

        return BitConverter.ToUInt32(b, 0);
    }

    public static (bool found, string? key, string? rawDumpBase64, string? error) TryReadOa3Key()
    {
        try
        {
            uint acpi = Sig("ACPI");
            uint msdm = Sig("MSDM");

            uint size = GetSystemFirmwareTable(acpi, msdm, IntPtr.Zero, 0);
            if (size == 0)
            {
                return (false, null, null, "MSDM table not present");
            }

            IntPtr buf = IntPtr.Zero;
            try
            {
                buf = Marshal.AllocHGlobal((int)size);
                uint read = GetSystemFirmwareTable(acpi, msdm, buf, size);
                if (read == 0 || read != size)
                {
                    return (false, null, null, "MSDM read failed");
                }

                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, (int)size);

                string ascii = Encoding.ASCII.GetString(data);
                var m = Regex.Match(ascii, @"[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}", RegexOptions.IgnoreCase);
                if (!m.Success)
                {
                    var sb = new StringBuilder(data.Length);
                    foreach (var b in data)
                    {
                        sb.Append(b >= 32 && b <= 126 ? (char)b : ' ');
                    }

                    m = Regex.Match(sb.ToString(), @"[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}", RegexOptions.IgnoreCase);
                }

                string? key = m.Success ? m.Value.ToUpperInvariant() : null;
                string dump = Convert.ToBase64String(data);
                return (key is not null, key, dump, key is null ? "Key not found in MSDM payload" : null);
            }
            finally
            {
                if (buf != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
        }
        catch (Exception ex)
        {
            return (false, null, null, ex.Message);
        }
    }
}
