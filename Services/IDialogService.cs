using System.Threading.Tasks;

namespace Intelicense.Services;

public interface IDialogService
{
    Task<bool> ShowConfirmationAsync(string title, string content);
    Task ShowMessageAsync(string title, string content);
}
