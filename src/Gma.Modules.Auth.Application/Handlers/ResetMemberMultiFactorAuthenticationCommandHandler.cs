namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class ResetMemberMultiFactorAuthenticationCommandHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    IMemberAuthenticationChallengeRepository challengeRepository,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : ICommandHandler<ResetMemberMultiFactorAuthenticationCommand, Unit>
{
    public async Task<Result<Unit>> HandleAsync(
        ResetMemberMultiFactorAuthenticationCommand command,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.MemberNotFound);
        }

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (authenticator is null)
        {
            return Result.Failure<Unit>(AuthDomainErrors.TotpAuthenticatorNotActive);
        }

        DateTimeOffset nowUtc = clock.UtcNow;
        bool wasActive = authenticator.IsActive;
        Result reset = authenticator.ResetByAdministrator(
            command.Reason,
            command.ActorId,
            idGenerator.NewId(),
            nowUtc);
        if (reset.IsFailure)
        {
            return Result.Failure<Unit>(reset.Error);
        }

        if (wasActive)
        {
            Result methodChanged = member.RecordAuthenticationMethodChanged(
                MemberAuthenticationMethods.Totp,
                MemberAuthenticationMethodChange.Removed,
                idGenerator.NewId(),
                nowUtc);
            if (methodChanged.IsFailure)
            {
                return Result.Failure<Unit>(methodChanged.Error);
            }
        }

        IReadOnlyList<MemberAuthenticationChallenge> challenges = await challengeRepository
            .GetActiveByMemberAsync(memberId, nowUtc, cancellationToken)
            .ConfigureAwait(false);
        foreach (MemberAuthenticationChallenge challenge in challenges)
        {
            challenge.Revoke(nowUtc);
        }

        Result<int> revoked = member.RevokeSessions(idGenerator.NewId(), nowUtc);
        return revoked.IsSuccess
            ? Result.Success(Unit.Value)
            : Result.Failure<Unit>(revoked.Error);
    }
}
