namespace Gma.Modules.Auth.Contracts;

public interface IAuthMemberAdmissionReader
{
    ValueTask<AuthMemberAdmission?> FindActiveAsync(
        string scopeId,
        Guid memberId,
        CancellationToken cancellationToken = default);
}
