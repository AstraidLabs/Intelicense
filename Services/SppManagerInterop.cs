using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Intelicense.Services;

public static class SppManagerInterop
{
    private static readonly Guid WindowsApplicationId = new("55C92734-D682-4D71-983E-D6EC3F16059F");

    public enum SlDataType : uint
    {
        None = 0,
        Sz = 1,
        Binary = 3,
        Dword = 4,
        MultiSz = 7,
    }

    public enum SlidType : uint
    {
        Application = 0,
        ProductSku = 1,
        LicenseFile = 2,
        License = 3,
        ProductKey = 4,
        AllLicenses = 5,
        AllLicenseFiles = 6,
        StoreToken = 7,
        Last = 8,
    }

    public enum SlLicensingStatusKind
    {
        Unlicensed = 0,
        Licensed = 1,
        InGracePeriod = 2,
        Notification = 3,
        Last = 4,
    }

    public enum SlGenuineState
    {
        Genuine = 0,
        InvalidLicense = 1,
        Tampered = 2,
        Offline = 3,
        Last = 4,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SlLicensingStatusNative
    {
        public Guid SkuId;
        public SlLicensingStatusKind Status;
        public uint GraceTimeMinutes;
        public uint TotalGraceDays;
        public int ReasonHResult;
        public ulong ValidityExpiration;
    }

    public readonly record struct SppValueResult(bool Success, SlDataType? DataType, string? StringValue, byte[]? BinaryValue, uint? DwordValue, int HResult, string? ErrorMessage)
    {
        public bool HasString => !string.IsNullOrWhiteSpace(StringValue);
        public bool HasBinary => BinaryValue is { Length: > 0 };
        public bool HasDword => DwordValue.HasValue;
    }

    public readonly record struct SlLicensingStatusEntry(Guid SkuId, SlLicensingStatusKind Status, uint GraceTimeMinutes, uint TotalGraceDays, int ReasonHResult, ulong ValidityExpiration);

    public readonly record struct SppLicensingStatusResult(bool Success, IReadOnlyList<SlLicensingStatusEntry> Entries, int HResult, string? ErrorMessage);

    public readonly record struct SppSlidListResult(bool Success, IReadOnlyList<Guid> Ids, int HResult, string? ErrorMessage);

    public readonly record struct SppGenuineResult(bool Success, SlGenuineState? State, int HResult, string? ErrorMessage);

    public static SppValueResult TryGetPKeyInformation(Guid pKeyId, string valueName)
    {
        if (!TryOpenContext(out var handle, out var hr, out var error))
        {
            return new SppValueResult(false, null, null, null, null, hr, error);
        }

        using (handle)
        {
            SlDataType dataType = SlDataType.None;
            uint size = 0;
            IntPtr buffer = IntPtr.Zero;
            string? callError = null;
            try
            {
                hr = handle.Library switch
                {
                    LibraryKind.Slc => NativeSlc.SLGetPKeyInformation(handle.DangerousGetHandle(), ref pKeyId, valueName, out dataType, out size, out buffer),
                    LibraryKind.Sppc => NativeSppc.SLGetPKeyInformation(handle.DangerousGetHandle(), ref pKeyId, valueName, out dataType, out size, out buffer),
                    _ => unchecked((int)0x80004005)
                };

                if (hr < 0 && callError is null)
                {
                    callError = FormatHResult(hr);
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }
            catch (Exception ex)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }

            return BuildValueResult(hr, dataType, size, buffer, callError);
        }
    }

    public static SppValueResult TryGetProductSkuInformation(Guid productSkuId, string valueName)
    {
        if (!TryOpenContext(out var handle, out var hr, out var error))
        {
            return new SppValueResult(false, null, null, null, null, hr, error);
        }

        using (handle)
        {
            SlDataType dataType = SlDataType.None;
            uint size = 0;
            IntPtr buffer = IntPtr.Zero;
            string? callError = null;
            try
            {
                hr = handle.Library switch
                {
                    LibraryKind.Slc => NativeSlc.SLGetProductSkuInformation(handle.DangerousGetHandle(), ref productSkuId, valueName, out dataType, out size, out buffer),
                    LibraryKind.Sppc => NativeSppc.SLGetProductSkuInformation(handle.DangerousGetHandle(), ref productSkuId, valueName, out dataType, out size, out buffer),
                    _ => unchecked((int)0x80004005)
                };

                if (hr < 0)
                {
                    callError = FormatHResult(hr);
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }
            catch (Exception ex)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }

            return BuildValueResult(hr, dataType, size, buffer, callError);
        }
    }

    public static SppValueResult TryGetServiceInformation(string valueName)
    {
        if (!TryOpenContext(out var handle, out var hr, out var error))
        {
            return new SppValueResult(false, null, null, null, null, hr, error);
        }

        using (handle)
        {
            SlDataType dataType = SlDataType.None;
            uint size = 0;
            IntPtr buffer = IntPtr.Zero;
            string? callError = null;
            try
            {
                hr = handle.Library switch
                {
                    LibraryKind.Slc => NativeSlc.SLGetServiceInformation(handle.DangerousGetHandle(), valueName, out dataType, out size, out buffer),
                    LibraryKind.Sppc => NativeSppc.SLGetServiceInformation(handle.DangerousGetHandle(), valueName, out dataType, out size, out buffer),
                    _ => unchecked((int)0x80004005)
                };

                if (hr < 0)
                {
                    callError = FormatHResult(hr);
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }
            catch (Exception ex)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }

            return BuildValueResult(hr, dataType, size, buffer, callError);
        }
    }

    public static SppValueResult TryGetWindowsInformationString(string valueName) => InvokeWindowsInformation(valueName);

    public static SppValueResult TryGetWindowsInformationDword(string valueName)
    {
        SlDataType dataType;
        uint size;
        IntPtr buffer;
        string? error;
        int hr = CallWindowsInformation(valueName, out dataType, out size, out buffer, out error);
        try
        {
            if (hr < 0)
            {
                return new SppValueResult(false, null, null, null, null, hr, error);
            }

            uint? value = null;
            if (dataType == SlDataType.Dword)
            {
                value = buffer != IntPtr.Zero ? (uint)Marshal.ReadInt32(buffer) : 0;
            }

            return new SppValueResult(true, dataType, null, null, value, hr, null);
        }
        finally
        {
            FreeMemory(buffer);
        }
    }

    public static SppLicensingStatusResult TryGetLicensingStatusInformation(Guid? appId, Guid? productSkuId, string? rightName = null)
    {
        if (!TryOpenContext(out var handle, out var hr, out var openError))
        {
            return new SppLicensingStatusResult(false, Array.Empty<SlLicensingStatusEntry>(), hr, openError);
        }

        using (handle)
        {
            IntPtr appPtr = IntPtr.Zero;
            IntPtr skuPtr = IntPtr.Zero;
            try
            {
                if (appId.HasValue)
                {
                    appPtr = AllocateGuid(appId.Value);
                }

                if (productSkuId.HasValue)
                {
                    skuPtr = AllocateGuid(productSkuId.Value);
                }

                uint count = 0;
                IntPtr statuses = IntPtr.Zero;
                string? callError = null;

                try
                {
                    hr = handle.Library switch
                    {
                        LibraryKind.Slc => NativeSlc.SLGetLicensingStatusInformation(handle.DangerousGetHandle(), appPtr, skuPtr, rightName, out count, out statuses),
                        LibraryKind.Sppc => NativeSppc.SLGetLicensingStatusInformation(handle.DangerousGetHandle(), appPtr, skuPtr, rightName, out count, out statuses),
                        _ => unchecked((int)0x80004005)
                    };

                    if (hr < 0)
                    {
                        callError = FormatHResult(hr);
                    }
                }
                catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
                {
                    callError = ex.Message;
                    hr = Marshal.GetHRForException(ex);
                }
                catch (Exception ex)
                {
                    callError = ex.Message;
                    hr = Marshal.GetHRForException(ex);
                }

                try
                {
                    if (hr < 0)
                    {
                        return new SppLicensingStatusResult(false, Array.Empty<SlLicensingStatusEntry>(), hr, callError);
                    }

                    if (count == 0 || statuses == IntPtr.Zero)
                    {
                        return new SppLicensingStatusResult(true, Array.Empty<SlLicensingStatusEntry>(), hr, null);
                    }

                    int structSize = Marshal.SizeOf<SlLicensingStatusNative>();
                    var entries = new List<SlLicensingStatusEntry>((int)count);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr current = statuses + (i * structSize);
                        var native = Marshal.PtrToStructure<SlLicensingStatusNative>(current);
                        entries.Add(new SlLicensingStatusEntry(native.SkuId, native.Status, native.GraceTimeMinutes, native.TotalGraceDays, native.ReasonHResult, native.ValidityExpiration));
                    }

                    return new SppLicensingStatusResult(true, entries, hr, null);
                }
                finally
                {
                    FreeMemory(statuses);
                }
            }
            finally
            {
                if (appPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(appPtr);
                }

                if (skuPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(skuPtr);
                }
            }
        }
    }

    public static SppValueResult TryGenerateOfflineInstallationId(Guid productSkuId)
    {
        if (!TryOpenContext(out var handle, out var hr, out var openError))
        {
            return new SppValueResult(false, null, null, null, null, hr, openError);
        }

        using (handle)
        {
            IntPtr buffer = IntPtr.Zero;
            string? callError = null;

            try
            {
                hr = handle.Library switch
                {
                    LibraryKind.Slc => NativeSlc.SLGenerateOfflineInstallationId(handle.DangerousGetHandle(), ref productSkuId, out buffer),
                    LibraryKind.Sppc => NativeSppc.SLGenerateOfflineInstallationId(handle.DangerousGetHandle(), ref productSkuId, out buffer),
                    _ => unchecked((int)0x80004005)
                };

                if (hr < 0)
                {
                    callError = FormatHResult(hr);
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }
            catch (Exception ex)
            {
                callError = ex.Message;
                hr = Marshal.GetHRForException(ex);
            }

            return BuildValueResult(hr, SlDataType.Sz, 0, buffer, callError);
        }
    }

    public static SppSlidListResult TryGetSlidList(SlidType queryType, Guid? queryId, SlidType returnType)
    {
        if (!TryOpenContext(out var handle, out var hr, out var openError))
        {
            return new SppSlidListResult(false, Array.Empty<Guid>(), hr, openError);
        }

        using (handle)
        {
            IntPtr queryPtr = IntPtr.Zero;
            if (queryId.HasValue)
            {
                queryPtr = AllocateGuid(queryId.Value);
            }

            try
            {
                uint count = 0;
                IntPtr ids = IntPtr.Zero;
                string? callError = null;
                try
                {
                    hr = handle.Library switch
                    {
                        LibraryKind.Slc => NativeSlc.SLGetSLIDList(handle.DangerousGetHandle(), queryType, queryPtr, returnType, out count, out ids),
                        LibraryKind.Sppc => NativeSppc.SLGetSLIDList(handle.DangerousGetHandle(), queryType, queryPtr, returnType, out count, out ids),
                        _ => unchecked((int)0x80004005)
                    };

                    if (hr < 0)
                    {
                        callError = FormatHResult(hr);
                    }
                }
                catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
                {
                    callError = ex.Message;
                    hr = Marshal.GetHRForException(ex);
                }
                catch (Exception ex)
                {
                    callError = ex.Message;
                    hr = Marshal.GetHRForException(ex);
                }

                try
                {
                    if (hr < 0)
                    {
                        return new SppSlidListResult(false, Array.Empty<Guid>(), hr, callError);
                    }

                    if (count == 0 || ids == IntPtr.Zero)
                    {
                        return new SppSlidListResult(true, Array.Empty<Guid>(), hr, null);
                    }

                    int guidSize = Marshal.SizeOf<Guid>();
                    var result = new Guid[count];
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr current = ids + (i * guidSize);
                        result[i] = Marshal.PtrToStructure<Guid>(current);
                    }

                    return new SppSlidListResult(true, result, hr, null);
                }
                finally
                {
                    FreeMemory(ids);
                }
            }
            finally
            {
                if (queryPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(queryPtr);
                }
            }
        }
    }

    public static SppGenuineResult TryIsWindowsGenuineLocal(Guid? appId = null, Guid? skuId = null)
    {
        Guid applicationId = appId ?? WindowsApplicationId;
        Guid sku = skuId ?? Guid.Empty;
        bool useSku = skuId.HasValue;
        SlGenuineState state = SlGenuineState.Last;
        int hr;
        string? error = null;

        try
        {
            if (useSku)
            {
                hr = NativeSlc.SLIsGenuineLocalEx(ref applicationId, ref sku, out state);
            }
            else
            {
                hr = NativeSlc.SLIsGenuineLocal(ref applicationId, out state, IntPtr.Zero);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = ex.Message;
            hr = Marshal.GetHRForException(ex);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            hr = Marshal.GetHRForException(ex);
        }

        if (error is not null || hr < 0)
        {
            try
            {
                if (useSku)
                {
                    hr = NativeSppc.SLIsGenuineLocalEx(ref applicationId, ref sku, out state);
                }
                else
                {
                    hr = NativeSppc.SLIsGenuineLocal(ref applicationId, out state, IntPtr.Zero);
                }

                error = hr < 0 ? FormatHResult(hr) : null;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                error = Combine(error, ex.Message);
                hr = Marshal.GetHRForException(ex);
            }
            catch (Exception ex)
            {
                error = Combine(error, ex.Message);
                hr = Marshal.GetHRForException(ex);
            }
        }

        if (hr < 0)
        {
            return new SppGenuineResult(false, null, hr, error ?? FormatHResult(hr));
        }

        return new SppGenuineResult(true, state, hr, null);
    }

    private static SppValueResult InvokeWindowsInformation(string valueName)
    {
        SlDataType dataType;
        uint size;
        IntPtr buffer;
        string? error;
        int hr = CallWindowsInformation(valueName, out dataType, out size, out buffer, out error);
        return BuildValueResult(hr, dataType, size, buffer, error);
    }

    private static int CallWindowsInformation(string valueName, out SlDataType dataType, out uint size, out IntPtr buffer, out string? error)
    {
        dataType = SlDataType.None;
        size = 0;
        buffer = IntPtr.Zero;
        error = null;
        int hr;

        try
        {
            hr = NativeSlc.SLGetWindowsInformation(valueName, out dataType, out size, out buffer);
            if (hr >= 0)
            {
                return hr;
            }

            error = FormatHResult(hr);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = ex.Message;
            hr = Marshal.GetHRForException(ex);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            hr = Marshal.GetHRForException(ex);
        }

        if (buffer != IntPtr.Zero)
        {
            FreeMemory(buffer);
            buffer = IntPtr.Zero;
            size = 0;
        }

        try
        {
            hr = NativeSppc.SLGetWindowsInformation(valueName, out dataType, out size, out buffer);
            if (hr >= 0)
            {
                error = null;
                return hr;
            }

            error = FormatHResult(hr);
            return hr;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = Combine(error, ex.Message);
            return Marshal.GetHRForException(ex);
        }
        catch (Exception ex)
        {
            error = Combine(error, ex.Message);
            return Marshal.GetHRForException(ex);
        }
    }

    private static SppValueResult BuildValueResult(int hr, SlDataType dataType, uint size, IntPtr buffer, string? error)
    {
        try
        {
            if (hr < 0)
            {
                return new SppValueResult(false, null, null, null, null, hr, error ?? FormatHResult(hr));
            }

            return dataType switch
            {
                SlDataType.Sz => new SppValueResult(true, dataType, PtrToUnicodeString(buffer), null, null, hr, null),
                SlDataType.MultiSz => new SppValueResult(true, dataType, PtrToMultiString(buffer, size), null, null, hr, null),
                SlDataType.Dword => new SppValueResult(true, dataType, null, null, buffer != IntPtr.Zero ? (uint)Marshal.ReadInt32(buffer) : 0, hr, null),
                SlDataType.Binary => new SppValueResult(true, dataType, null, CopyBinary(buffer, size), null, hr, null),
                _ => new SppValueResult(true, dataType, string.Empty, CopyBinary(buffer, size), null, hr, null),
            };
        }
        finally
        {
            FreeMemory(buffer);
        }
    }

    private static string PtrToUnicodeString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return string.Empty;
        }

        return Marshal.PtrToStringUni(ptr) ?? string.Empty;
    }

    private static string PtrToMultiString(IntPtr ptr, uint size)
    {
        if (ptr == IntPtr.Zero || size == 0)
        {
            return string.Empty;
        }

        int charCount = (int)(size / 2);
        if (charCount <= 0)
        {
            return string.Empty;
        }

        var chars = new char[charCount];
        Marshal.Copy(ptr, chars, 0, charCount);

        var builder = new StringBuilder();
        var segments = new List<string>();
        foreach (char c in chars)
        {
            if (c == '\0')
            {
                if (builder.Length == 0)
                {
                    break;
                }

                segments.Add(builder.ToString());
                builder.Clear();
                continue;
            }

            builder.Append(c);
        }

        if (builder.Length > 0)
        {
            segments.Add(builder.ToString());
        }

        return segments.Count == 0 ? string.Empty : string.Join(Environment.NewLine, segments);
    }

    private static byte[]? CopyBinary(IntPtr ptr, uint size)
    {
        if (ptr == IntPtr.Zero || size == 0)
        {
            return Array.Empty<byte>();
        }

        var data = new byte[size];
        Marshal.Copy(ptr, data, 0, (int)size);
        return data;
    }

    private static bool TryOpenContext(out SafeSlcHandle handle, out int hr, out string? error)
    {
        handle = new SafeSlcHandle();
        hr = 0;
        error = null;

        try
        {
            hr = NativeSlc.SLOpen(out var raw);
            if (hr >= 0 && raw != IntPtr.Zero)
            {
                handle = new SafeSlcHandle(raw, LibraryKind.Slc);
                return true;
            }

            if (hr < 0)
            {
                error = FormatHResult(hr);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = ex.Message;
            hr = Marshal.GetHRForException(ex);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            hr = Marshal.GetHRForException(ex);
        }

        try
        {
            int hrSppc = NativeSppc.SLOpen(out var rawSppc);
            if (hrSppc >= 0 && rawSppc != IntPtr.Zero)
            {
                handle = new SafeSlcHandle(rawSppc, LibraryKind.Sppc);
                hr = hrSppc;
                error = null;
                return true;
            }

            if (hrSppc < 0)
            {
                error = Combine(error, FormatHResult(hrSppc));
                hr = hrSppc;
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = Combine(error, ex.Message);
            hr = Marshal.GetHRForException(ex);
        }
        catch (Exception ex)
        {
            error = Combine(error, ex.Message);
            hr = Marshal.GetHRForException(ex);
        }

        return false;
    }

    private static string? Combine(string? first, string? second)
    {
        if (string.IsNullOrWhiteSpace(first))
        {
            return second;
        }

        if (string.IsNullOrWhiteSpace(second))
        {
            return first;
        }

        return first + "; " + second;
    }

    private static string FormatHResult(int hr)
    {
        string hex = $"0x{hr:X8}";
        try
        {
            var message = Marshal.GetExceptionForHR(hr)?.Message;
            if (!string.IsNullOrWhiteSpace(message))
            {
                return hex + ": " + message;
            }
        }
        catch
        {
            // Ignore lookup failures.
        }

        try
        {
            var description = new Win32Exception(hr).Message;
            if (!string.IsNullOrWhiteSpace(description))
            {
                return hex + ": " + description;
            }
        }
        catch
        {
            // Ignore mapping failures.
        }

        return hex;
    }

    private static IntPtr AllocateGuid(Guid value)
    {
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        Marshal.StructureToPtr(value, ptr, false);
        return ptr;
    }

    private static void FreeMemory(IntPtr pointer)
    {
        if (pointer != IntPtr.Zero)
        {
            LocalFree(pointer);
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private enum LibraryKind
    {
        None,
        Slc,
        Sppc,
    }

    private sealed class SafeSlcHandle : SafeHandle
    {
        internal SafeSlcHandle()
            : base(IntPtr.Zero, true)
        {
            Library = LibraryKind.None;
        }

        internal SafeSlcHandle(IntPtr handle, LibraryKind library)
            : base(IntPtr.Zero, true)
        {
            SetHandle(handle);
            Library = library;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        internal LibraryKind Library { get; }

        protected override bool ReleaseHandle()
        {
            if (IsInvalid)
            {
                return true;
            }

            try
            {
                switch (Library)
                {
                    case LibraryKind.Slc:
                        NativeSlc.SLClose(handle);
                        break;
                    case LibraryKind.Sppc:
                        NativeSppc.SLClose(handle);
                        break;
                }
            }
            catch
            {
                // Ignore release errors.
            }

            handle = IntPtr.Zero;
            return true;
        }
    }

    private static class NativeSlc
    {
        private const string LibraryName = "slc.dll";

        [DllImport(LibraryName)]
        internal static extern int SLOpen(out IntPtr phSlc);

        [DllImport(LibraryName)]
        internal static extern int SLClose(IntPtr hSlc);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetPKeyInformation(IntPtr hSlc, ref Guid pKeyId, string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetProductSkuInformation(IntPtr hSlc, ref Guid productSkuId, string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetServiceInformation(IntPtr hSlc, string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetLicensingStatusInformation(IntPtr hSlc, IntPtr appId, IntPtr productSkuId, string? rightName, out uint statusCount, out IntPtr licensingStatus);

        [DllImport(LibraryName)]
        internal static extern int SLGetSLIDList(IntPtr hSlc, SlidType queryType, IntPtr queryId, SlidType returnType, out uint returnIds, out IntPtr ids);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGenerateOfflineInstallationId(IntPtr hSlc, ref Guid productSkuId, out IntPtr installationId);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetWindowsInformation(string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLIsGenuineLocal(ref Guid appId, out SlGenuineState state, IntPtr options);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLIsGenuineLocalEx(ref Guid appId, ref Guid skuId, out SlGenuineState state);
    }

    private static class NativeSppc
    {
        private const string LibraryName = "sppc.dll";

        [DllImport(LibraryName)]
        internal static extern int SLOpen(out IntPtr phSlc);

        [DllImport(LibraryName)]
        internal static extern int SLClose(IntPtr hSlc);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetPKeyInformation(IntPtr hSlc, ref Guid pKeyId, string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetProductSkuInformation(IntPtr hSlc, ref Guid productSkuId, string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetServiceInformation(IntPtr hSlc, string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetLicensingStatusInformation(IntPtr hSlc, IntPtr appId, IntPtr productSkuId, string? rightName, out uint statusCount, out IntPtr licensingStatus);

        [DllImport(LibraryName)]
        internal static extern int SLGetSLIDList(IntPtr hSlc, SlidType queryType, IntPtr queryId, SlidType returnType, out uint returnIds, out IntPtr ids);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGenerateOfflineInstallationId(IntPtr hSlc, ref Guid productSkuId, out IntPtr installationId);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLGetWindowsInformation(string valueName, out SlDataType dataType, out uint size, out IntPtr buffer);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLIsGenuineLocal(ref Guid appId, out SlGenuineState state, IntPtr options);

        [DllImport(LibraryName, CharSet = CharSet.Unicode)]
        internal static extern int SLIsGenuineLocalEx(ref Guid appId, ref Guid skuId, out SlGenuineState state);
    }
}
