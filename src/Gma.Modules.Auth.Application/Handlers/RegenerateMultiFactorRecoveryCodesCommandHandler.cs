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
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class RegenerateMultiFactorRecoveryCodesCommandHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
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
        ICommandHandler<RegenerateMultiFactorRecoveryCodesCommand, MultiFactorRecoveryCodeRegenerationCompletion>
{
    public async Task<Result<MultiFactorRecoveryCodeRegenerationCompletion>> HandleAsync(
        RegenerateMultiFactorRecoveryCodesCommand command,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null ||
            (scopeContext.IsEnabled && !string.Equals(scopeContext.ScopeId, member.ScopeId, StringComparison.Ordinal)))
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(AuthDomainErrors.MemberNotFound);
        }

        MemberSession? session = member.Sessions.FirstOrDefault(item =>
            item.Id == new MemberSessionId(command.SessionId) && item.IsActive);
        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (session is null || authenticator is null || !authenticator.IsActive)
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(AuthApplicationErrors.TotpAuthenticatorNotActive);
        }

        DateTimeOffset nowUtc = this.Clock.UtcNow;
        string limiterTarget = command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture);
        int recentFailureCount = await failureAttemptRepository.CountSinceAsync(
            memberId,
            MemberMultiFactorFailureAttempt.ManagementPurpose,
            nowUtc.AddMinutes(-options.Value.MultiFactor.ManagementAttemptWindowMinutes),
            cancellationToken).ConfigureAwait(false);
        if (recentFailureCount >= options.Value.MultiFactor.ManagementMaximumAttempts)
        {
            return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Invalid);
        }

        if (!await attemptLimiter.IsAllowedAsync(
                member.ScopeId,
                AuthenticationAttemptPurposes.MultiFactorManagement,
                limiterTarget,
                nowUtc,
                cancellationToken).ConfigureAwait(false))
        {
            return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Invalid);
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
                return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(factor.Error);
            }

            await attemptLimiter.RecordFailureAsync(
                member.ScopeId,
                AuthenticationAttemptPurposes.MultiFactorManagement,
                limiterTarget,
                nowUtc,
                cancellationToken).ConfigureAwait(false);
            Result<MemberMultiFactorFailureAttempt> failedAttempt = MemberMultiFactorFailureAttempt.Create(
                new MemberMultiFactorFailureAttemptId(this.IdGenerator.NewId()),
                memberId,
                member.ScopeId,
                MemberMultiFactorFailureAttempt.ManagementPurpose,
                nowUtc);
            if (failedAttempt.IsFailure)
            {
                return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(failedAttempt.Error);
            }

            await failureAttemptRepository.AddAsync(failedAttempt.Value, cancellationToken).ConfigureAwait(false);
            return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Invalid);
        }

        IReadOnlyList<RecoveryCodeMaterial> recoveryCodes = multiFactorAuthentication.GenerateRecoveryCodes();
        Result regenerated = authenticator.RegenerateRecoveryCodes(
            multiFactorAuthentication.CreateRecoveryCodeRegistrations(recoveryCodes),
            nowUtc);
        if (regenerated.IsFailure)
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(regenerated.Error);
        }

        string refreshToken = this.GenerateRefreshToken();
        Result<MemberSession> reauthenticated = member.ReauthenticateSession(
            session.Id,
            this.TokenHashingService.GetCandidateHashes(command.RefreshToken),
            this.TokenHashingService.HashRefreshToken(refreshToken),
            nowUtc.AddDays(options.Value.RefreshTokenLifetimeDays),
            factor.Value,
            this.IdGenerator.NewId(),
            nowUtc);
        if (reauthenticated.IsFailure)
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(reauthenticated.Error);
        }

        await attemptLimiter.RecordSuccessAsync(
            member.ScopeId,
            AuthenticationAttemptPurposes.MultiFactorManagement,
            limiterTarget,
            cancellationToken).ConfigureAwait(false);
        return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Completed(
            new MultiFactorRecoveryCodesResponse(
                this.CreateAccessToken(member, reauthenticated.Value),
                refreshToken,
                recoveryCodes.Select(code => code.Plaintext).ToArray())));
    }

    private static SessionAuthenticationEvidence CreatePrimaryEvidence(
        string authenticationMethod,
        DateTimeOffset nowUtc) =>
        string.Equals(authenticationMethod, MemberAuthenticationMethods.Password, StringComparison.Ordinal)
            ? SessionAuthenticationEvidence.Password(nowUtc)
            : SessionAuthenticationEvidence.External(nowUtc);
}
