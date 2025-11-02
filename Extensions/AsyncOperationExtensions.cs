using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;

namespace Intelicense.Extensions;

internal static class AsyncOperationExtensions
{
    public static Task<T> AsTask<T>(this IAsyncOperation<T> operation)
    {
        if (operation is null)
        {
            throw new ArgumentNullException(nameof(operation));
        }

        switch (operation.Status)
        {
            case AsyncStatus.Completed:
                return Task.FromResult(operation.GetResults());
            case AsyncStatus.Canceled:
                return Task.FromCanceled<T>(new CancellationToken(true));
            case AsyncStatus.Error:
                return Task.FromException<T>(operation.ErrorCode);
        }

        var completionSource = new TaskCompletionSource<T>();

        operation.Completed = (op, status) =>
        {
            switch (status)
            {
                case AsyncStatus.Completed:
                    completionSource.TrySetResult(op.GetResults());
                    break;
                case AsyncStatus.Canceled:
                    completionSource.TrySetCanceled();
                    break;
                case AsyncStatus.Error:
                    completionSource.TrySetException(op.ErrorCode);
                    break;
            }
        };

        return completionSource.Task;
    }
}
