namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed class MemberMultiFactorFailureAttemptRepository(AuthDbContext dbContext)
    : IMemberMultiFactorFailureAttemptRepository
{
    public Task<int> CountSinceAsync(
        MemberId memberId,
        string purpose,
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken) =>
        dbContext.MemberMultiFactorFailureAttempts.CountAsync(
            attempt =>
                attempt.MemberId == memberId &&
                attempt.Purpose == purpose &&
                attempt.FailedAtUtc >= sinceUtc,
            cancellationToken);

    public async Task AddAsync(MemberMultiFactorFailureAttempt attempt, CancellationToken cancellationToken) =>
        await dbContext.MemberMultiFactorFailureAttempts.AddAsync(attempt, cancellationToken).ConfigureAwait(false);
}
