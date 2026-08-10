namespace Gma.Modules.Auth.Contracts;

public interface IAuthSessionAdmissionReader
{
    ValueTask<bool> IsActiveAsync(
        string scopeId,
        Guid memberId,
        Guid sessionId,
        CancellationToken cancellationToken = default);
}
