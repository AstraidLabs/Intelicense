using System.Threading.Tasks;

namespace Intelicense.Services;

public interface IFileService
{
    Task<bool> SaveJsonAsync(string suggestedFileName, string jsonContent);
}
