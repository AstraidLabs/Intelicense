using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Intelicense.Extensions;
using Microsoft.UI.Xaml;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Intelicense.Services;

public sealed class FileService : IFileService
{
    private readonly Window _window;

    public FileService(Window window)
    {
        _window = window;
    }

    public async Task<bool> SaveJsonAsync(string suggestedFileName, string jsonContent)
    {
        if (_window.Content is not FrameworkElement)
        {
            return false;
        }

        var picker = new FileSavePicker
        {
            SuggestedFileName = suggestedFileName,
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary
        };

        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(_window));

        picker.FileTypeChoices.Add("JSON", new List<string> { ".json" });

        var file = await picker.PickSaveFileAsync().AsTask();
        if (file is null)
        {
            return false;
        }

        await FileIO.WriteTextAsync(file, jsonContent);
        return true;
    }
}
