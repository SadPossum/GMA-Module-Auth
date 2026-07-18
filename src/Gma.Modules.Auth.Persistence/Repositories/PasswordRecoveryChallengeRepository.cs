namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed class PasswordRecoveryChallengeRepository(AuthDbContext dbContext)
    : IPasswordRecoveryChallengeRepository
{
    public Task<PasswordRecoveryChallenge?> GetLatestByMemberAsync(
        MemberId memberId,
        CancellationToken cancellationToken) =>
        dbContext.PasswordRecoveryChallenges
            .OrderByDescending(challenge => challenge.RequestedAtUtc)
            .FirstOrDefaultAsync(challenge => challenge.MemberId == memberId, cancellationToken);

    public async Task<IReadOnlyList<PasswordRecoveryChallenge>> GetActiveByMemberAsync(
        MemberId memberId,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken) =>
        await dbContext.PasswordRecoveryChallenges
            .Where(challenge =>
                challenge.MemberId == memberId &&
                challenge.ConsumedAtUtc == null &&
                challenge.RevokedAtUtc == null &&
                challenge.ExpiresAtUtc > nowUtc)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    public Task<PasswordRecoveryChallenge?> GetByTokenHashesAsync(
        IReadOnlyCollection<string> tokenHashes,
        CancellationToken cancellationToken)
    {
        string[] hashes = [.. tokenHashes.Distinct(StringComparer.Ordinal)];
        return dbContext.PasswordRecoveryChallenges.SingleOrDefaultAsync(
            challenge => hashes.Contains(challenge.TokenHash),
            cancellationToken);
    }

    public async Task AddAsync(PasswordRecoveryChallenge challenge, CancellationToken cancellationToken) =>
        await dbContext.PasswordRecoveryChallenges.AddAsync(challenge, cancellationToken).ConfigureAwait(false);
}
