namespace Gma.Modules.Auth.Domain.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

public interface IMemberAuthenticationChallengeRepository
{
    Task<MemberAuthenticationChallenge?> GetByTokenHashesAsync(
        IReadOnlyCollection<string> tokenHashes,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<MemberAuthenticationChallenge>> GetActiveByMemberAsync(
        MemberId memberId,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken);

    Task AddAsync(MemberAuthenticationChallenge challenge, CancellationToken cancellationToken);
}
