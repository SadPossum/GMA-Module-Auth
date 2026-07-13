namespace Gma.Modules.Auth.Contracts;

public interface IAuthMemberContactReader
{
    ValueTask<string?> GetPreferredVerifiedEmailAsync(
        string scopeId,
        Guid memberId,
        CancellationToken cancellationToken = default);
}
