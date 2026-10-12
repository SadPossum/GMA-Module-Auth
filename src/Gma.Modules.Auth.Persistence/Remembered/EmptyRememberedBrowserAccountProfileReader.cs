namespace Gma.Modules.Auth.Persistence.Remembered;

using Gma.Modules.Auth.Application.Ports;

internal sealed class EmptyRememberedBrowserAccountProfileReader : IRememberedBrowserAccountProfileReader
{
    public Task<RememberedBrowserAccountProfile?> FindAsync(
        string scopeId,
        Guid memberId,
        CancellationToken cancellationToken) => Task.FromResult<RememberedBrowserAccountProfile?>(null);
}
