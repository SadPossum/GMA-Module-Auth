namespace Gma.Modules.Auth.Domain.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

public interface IMemberMultiFactorFailureAttemptRepository
{
    Task<int> CountSinceAsync(
        MemberId memberId,
        string purpose,
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken);

    Task AddAsync(MemberMultiFactorFailureAttempt attempt, CancellationToken cancellationToken);
}
