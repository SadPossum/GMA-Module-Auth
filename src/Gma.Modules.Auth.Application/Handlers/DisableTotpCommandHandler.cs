namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class DisableTotpCommandHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    IMemberAuthenticationChallengeRepository challengeRepository,
    IMemberMultiFactorFailureAttemptRepository failureAttemptRepository,
    MultiFactorAuthenticationService multiFactorAuthentication,
    IAuthenticationAttemptLimiter attemptLimiter,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<DisableTotpCommand, MultiFactorDisableCompletion>
{
    public async Task<Result<MultiFactorDisableCompletion>> HandleAsync(
        DisableTotpCommand command,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null ||
            (scopeContext.IsEnabled && !string.Equals(scopeContext.ScopeId, member.ScopeId, StringComparison.Ordinal)))
        {
            return Result.Failure<MultiFactorDisableCompletion>(AuthDomainErrors.MemberNotFound);
        }

        MemberSession? session = member.Sessions.FirstOrDefault(item =>
            item.Id == new MemberSessionId(command.SessionId) && item.IsActive);
        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (session is null || authenticator is null || !authenticator.IsActive)
        {
            return Result.Failure<MultiFactorDisableCompletion>(AuthApplicationErrors.TotpAuthenticatorNotActive);
        }

        DateTimeOffset nowUtc = this.Clock.UtcNow;
        string limiterKey = $"member:{command.MemberId:D}:mfa-management";
        int recentFailureCount = await failureAttemptRepository.CountSinceAsync(
            memberId,
            MemberMultiFactorFailureAttempt.ManagementPurpose,
            nowUtc.AddMinutes(-options.Value.MultiFactor.ManagementAttemptWindowMinutes),
            cancellationToken).ConfigureAwait(false);
        if (recentFailureCount >= options.Value.MultiFactor.ManagementMaximumAttempts)
        {
            return Result.Success(MultiFactorDisableCompletion.Invalid);
        }

        if (!attemptLimiter.IsAllowed(member.ScopeId, limiterKey, nowUtc))
        {
            return Result.Success(MultiFactorDisableCompletion.Invalid);
        }

        Result<SessionAuthenticationEvidence> factor = multiFactorAuthentication.VerifyFactor(
            authenticator,
            CreatePrimaryEvidence(session.AuthenticationMethod, nowUtc),
            command.CodeType,
            command.Code,
            nowUtc);
        if (factor.IsFailure)
        {
            if (factor.Error == AuthApplicationErrors.MultiFactorProviderUnavailable)
            {
                return Result.Failure<MultiFactorDisableCompletion>(factor.Error);
            }

            attemptLimiter.RecordFailure(member.ScopeId, limiterKey, nowUtc);
            Result<MemberMultiFactorFailureAttempt> failedAttempt = MemberMultiFactorFailureAttempt.Create(
                new MemberMultiFactorFailureAttemptId(this.IdGenerator.NewId()),
                memberId,
                member.ScopeId,
                MemberMultiFactorFailureAttempt.ManagementPurpose,
                nowUtc);
            if (failedAttempt.IsFailure)
            {
                return Result.Failure<MultiFactorDisableCompletion>(failedAttempt.Error);
            }

            await failureAttemptRepository.AddAsync(failedAttempt.Value, cancellationToken).ConfigureAwait(false);
            return Result.Success(MultiFactorDisableCompletion.Invalid);
        }

        string discardedRefreshToken = this.GenerateRefreshToken();
        Result<MemberSession> reauthenticated = member.ReauthenticateSession(
            session.Id,
            this.TokenHashingService.GetCandidateHashes(command.RefreshToken),
            this.TokenHashingService.HashRefreshToken(discardedRefreshToken),
            nowUtc.AddDays(options.Value.RefreshTokenLifetimeDays),
            factor.Value,
            this.IdGenerator.NewId(),
            nowUtc);
        if (reauthenticated.IsFailure)
        {
            return Result.Failure<MultiFactorDisableCompletion>(reauthenticated.Error);
        }

        Result disabled = authenticator.Disable(nowUtc);
        if (disabled.IsFailure)
        {
            return Result.Failure<MultiFactorDisableCompletion>(disabled.Error);
        }

        Result methodChanged = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Totp,
            MemberAuthenticationMethodChange.Removed,
            this.IdGenerator.NewId(),
            nowUtc);
        if (methodChanged.IsFailure)
        {
            return Result.Failure<MultiFactorDisableCompletion>(methodChanged.Error);
        }

        IReadOnlyList<MemberAuthenticationChallenge> challenges = await challengeRepository
            .GetActiveByMemberAsync(memberId, nowUtc, cancellationToken)
            .ConfigureAwait(false);
        foreach (MemberAuthenticationChallenge challenge in challenges)
        {
            challenge.Revoke(nowUtc);
        }

        Result<int> revoked = member.RevokeSessions(this.IdGenerator.NewId(), nowUtc);
        if (revoked.IsFailure)
        {
            return Result.Failure<MultiFactorDisableCompletion>(revoked.Error);
        }

        attemptLimiter.RecordSuccess(member.ScopeId, limiterKey);
        return Result.Success(MultiFactorDisableCompletion.Completed);
    }

    private static SessionAuthenticationEvidence CreatePrimaryEvidence(
        string authenticationMethod,
        DateTimeOffset nowUtc) =>
        string.Equals(authenticationMethod, MemberAuthenticationMethods.Password, StringComparison.Ordinal)
            ? SessionAuthenticationEvidence.Password(nowUtc)
            : SessionAuthenticationEvidence.External(nowUtc);
}
