namespace Gma.Modules.Auth.Domain.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

public interface IMemberRepository
{
    Task<Member?> GetByIdAsync(MemberId id, CancellationToken cancellationToken);
    Task<Member?> GetByUsernameAsync(string username, CancellationToken cancellationToken);
    Task<Member?> GetByExternalIdentityAsync(string issuer, string subject, CancellationToken cancellationToken);
    Task<bool> UsernameExistsAsync(string username, CancellationToken cancellationToken);
    Task<bool> ExternalIdentityExistsAsync(string issuer, string subject, CancellationToken cancellationToken);
    Task<EmailVerificationTarget?> GetByEmailVerificationTokenHashesAsync(
        IReadOnlyCollection<string> verificationTokenHashes,
        CancellationToken cancellationToken);
    Task AddAsync(Member member, CancellationToken cancellationToken);
}

public sealed record EmailVerificationTarget(
    Member Member,
    MemberUsernameId UsernameId,
    string MatchedTokenHash);
