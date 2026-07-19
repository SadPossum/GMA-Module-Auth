namespace Gma.Modules.Auth.Application.Security;

public interface IAuthenticationAttemptLimiter
{
    ValueTask<bool> IsAllowedAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken);

    ValueTask RecordFailureAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken);

    ValueTask RecordSuccessAsync(
        string scopeId,
        string purpose,
        string target,
        CancellationToken cancellationToken);
}
