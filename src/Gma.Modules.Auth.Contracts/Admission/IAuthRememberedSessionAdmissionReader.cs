namespace Gma.Modules.Auth.Contracts;

public interface IAuthRememberedSessionAdmissionReader
{
    Task<bool> IsAdmittedAsync(
        string scopeId,
        Guid memberId,
        Guid sessionId,
        string? deviceCredential,
        CancellationToken cancellationToken = default);
}
