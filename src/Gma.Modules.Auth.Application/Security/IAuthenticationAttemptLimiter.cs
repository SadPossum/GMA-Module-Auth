namespace Gma.Modules.Auth.Application.Security;

public interface IAuthenticationAttemptLimiter
{
    ValueTask<AuthenticationAttemptLease?> TryAcquireAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        AuthenticationAttemptPolicy policy,
        CancellationToken cancellationToken);

    ValueTask RecordSuccessAsync(
        string scopeId,
        string purpose,
        string target,
        AuthenticationAttemptLease lease,
        CancellationToken cancellationToken);
}
