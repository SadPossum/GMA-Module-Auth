namespace Gma.Modules.Auth.Application.Ports;

public interface IRememberedBrowserAccountProfileReader
{
    Task<RememberedBrowserAccountProfile?> FindAsync(
        string scopeId,
        Guid memberId,
        CancellationToken cancellationToken);
}

public sealed record RememberedBrowserAccountProfile(
    string DisplayName,
    string? JobTitle);
