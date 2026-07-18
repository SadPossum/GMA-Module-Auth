namespace Gma.Modules.Auth.Domain.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

public interface IPasswordRecoveryChallengeRepository
{
    Task<PasswordRecoveryChallenge?> GetLatestByMemberAsync(
        MemberId memberId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<PasswordRecoveryChallenge>> GetActiveByMemberAsync(
        MemberId memberId,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken);

    Task<PasswordRecoveryChallenge?> GetByTokenHashesAsync(
        IReadOnlyCollection<string> tokenHashes,
        CancellationToken cancellationToken);

    Task AddAsync(PasswordRecoveryChallenge challenge, CancellationToken cancellationToken);
}
