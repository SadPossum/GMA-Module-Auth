namespace Gma.Modules.Auth.Application.Security;

public interface IAuthenticationAttemptLimiter
{
    bool IsAllowed(string scopeId, string username, DateTimeOffset nowUtc);
    void RecordFailure(string scopeId, string username, DateTimeOffset nowUtc);
    void RecordSuccess(string scopeId, string username);
}
