using System.Threading;
using System.Threading.Tasks;
using Intelicense.Models;

namespace Intelicense.Services;

public interface IWindowsLicenseService
{
    Task<WindowsLicenseInfo> GatherLicenseInfoAsync(bool includeSensitive, bool usePowerShellFallback, CancellationToken cancellationToken);
}
