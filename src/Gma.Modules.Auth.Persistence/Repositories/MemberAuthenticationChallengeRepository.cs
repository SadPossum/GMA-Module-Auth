namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed class MemberAuthenticationChallengeRepository(AuthDbContext dbContext)
    : IMemberAuthenticationChallengeRepository
{
    public Task<MemberAuthenticationChallenge?> GetByTokenHashesAsync(
        IReadOnlyCollection<string> tokenHashes,
        CancellationToken cancellationToken)
    {
        string[] hashes = [.. tokenHashes.Distinct(StringComparer.Ordinal)];
        return dbContext.MemberAuthenticationChallenges.SingleOrDefaultAsync(
            challenge => hashes.Contains(challenge.TokenHash),
            cancellationToken);
    }

    public async Task<IReadOnlyList<MemberAuthenticationChallenge>> GetActiveByMemberAsync(
        MemberId memberId,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken) =>
        await dbContext.MemberAuthenticationChallenges
            .Where(challenge =>
                challenge.MemberId == memberId &&
                challenge.ConsumedAtUtc == null &&
                challenge.RevokedAtUtc == null &&
                challenge.ExpiresAtUtc > nowUtc &&
                challenge.FailedAttemptCount < challenge.MaximumAttempts)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    public async Task AddAsync(MemberAuthenticationChallenge challenge, CancellationToken cancellationToken) =>
        await dbContext.MemberAuthenticationChallenges.AddAsync(challenge, cancellationToken).ConfigureAwait(false);
}
