using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;

namespace Intelicense.Services;

public sealed class ClipboardService : IClipboardService
{
    public Task CopyTextAsync(string text)
    {
        var dataPackage = new DataPackage();
        dataPackage.SetText(text);
        Clipboard.SetContent(dataPackage);
        Clipboard.Flush();
        return Task.CompletedTask;
    }
}
