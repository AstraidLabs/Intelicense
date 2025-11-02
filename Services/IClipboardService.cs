using System.Threading.Tasks;

namespace Intelicense.Services;

public interface IClipboardService
{
    Task CopyTextAsync(string text);
}
