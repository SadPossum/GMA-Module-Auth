namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class ConfirmPasswordRecoveryCommandHandler(
    IPasswordRecoveryChallengeRepository challengeRepository,
    IMemberRepository memberRepository,
    IPasswordRecoveryTokenService tokenService,
    IPasswordHashingService passwordHashingService,
    IPasswordBlocklist passwordBlocklist,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : ICommandHandler<ConfirmPasswordRecoveryCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(
        ConfirmPasswordRecoveryCommand command,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> candidateHashes = tokenService.GetCandidateHashes(command.Code.Trim());
        PasswordRecoveryChallenge? challenge = await challengeRepository
            .GetByTokenHashesAsync(candidateHashes, cancellationToken)
            .ConfigureAwait(false);
        DateTimeOffset challengeCheckedAtUtc = clock.UtcNow;
        if (challenge is null || !challenge.IsActiveAt(challengeCheckedAtUtc))
        {
            return Invalid();
        }

        Member? member = await memberRepository
            .GetByIdAsync(challenge.MemberId, cancellationToken)
            .ConfigureAwait(false);
        if (member is null ||
            member.Status != MemberStatus.Active ||
            !member.HasPassword ||
            !member.Usernames.Any(username =>
                username.UsernameType == MemberUsernameType.Email &&
                username.IsActive &&
                username.IsVerified &&
                string.Equals(username.Value, challenge.Email, StringComparison.OrdinalIgnoreCase)))
        {
            return Invalid();
        }

        if (await passwordBlocklist.IsBlockedAsync(command.NewPassword, cancellationToken).ConfigureAwait(false))
        {
            return Result.Failure<Unit>(AuthApplicationErrors.PasswordBlocked);
        }

        DateTimeOffset nowUtc = clock.UtcNow;
        if (!challenge.IsActiveAt(nowUtc))
        {
            return Invalid();
        }

        IReadOnlyList<PasswordRecoveryChallenge> activeChallenges = await challengeRepository
            .GetActiveByMemberAsync(member.Id, nowUtc, cancellationToken)
            .ConfigureAwait(false);
        string matchedHash = candidateHashes.First(hash =>
            string.Equals(hash, challenge.TokenHash, StringComparison.Ordinal));
        Result consumed = challenge.Consume(matchedHash, nowUtc);
        if (consumed.IsFailure)
        {
            return Invalid();
        }

        foreach (PasswordRecoveryChallenge activeChallenge in activeChallenges.Where(item => item.Id != challenge.Id))
        {
            activeChallenge.Revoke(nowUtc);
        }

        Result reset = member.ResetPassword(passwordHashingService.HashPassword(command.NewPassword));
        if (reset.IsFailure)
        {
            return Result.Failure<Unit>(reset.Error);
        }

        Result<int> revoked = member.RevokeSessions(idGenerator.NewId(), nowUtc);
        if (revoked.IsFailure)
        {
            return Result.Failure<Unit>(revoked.Error);
        }

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Password,
            MemberAuthenticationMethodChange.Updated,
            idGenerator.NewId(),
            nowUtc);
        return changed.IsSuccess ? Result.Success(Unit.Value) : Result.Failure<Unit>(changed.Error);
    }

    private static Result<Unit> Invalid() => Result.Failure<Unit>(AuthApplicationErrors.PasswordRecoveryInvalid);
}
