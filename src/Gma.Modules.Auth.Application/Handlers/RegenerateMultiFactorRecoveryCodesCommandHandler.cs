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

        IReadOnlyList<string> candidateRefreshTokenHashes =
            this.TokenHashingService.GetCandidateHashes(command.RefreshToken);
        Result<MemberSession> refreshProof = member.VerifySessionRefreshTokenAndHandleReuse(
            new MemberSessionId(command.SessionId),
            candidateRefreshTokenHashes,
            this.IdGenerator.NewId(),
            this.Clock.UtcNow);
        if (refreshProof.IsFailure)
        {
            return refreshProof.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.ReuseDetected)
                : Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(refreshProof.Error);
        }

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (authenticator is null || !authenticator.IsActive)
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(AuthApplicationErrors.TotpAuthenticatorNotActive);
        }

        DateTimeOffset attemptCheckedAtUtc = this.Clock.UtcNow;
        string limiterTarget = command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture);
        int recentFailureCount = await failureAttemptRepository.CountSinceAsync(
            memberId,
            MemberMultiFactorFailureAttempt.ManagementPurpose,
            attemptCheckedAtUtc.AddMinutes(-options.Value.MultiFactor.ManagementAttemptWindowMinutes),
            cancellationToken).ConfigureAwait(false);
        if (recentFailureCount >= options.Value.MultiFactor.ManagementMaximumAttempts)
        {
            return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Invalid);
        }

        if (command.CodeType == MultiFactorCodeType.Totp && !multiFactorAuthentication.TotpProviderAvailable)
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(
                AuthApplicationErrors.MultiFactorProviderUnavailable);
        }

        AuthenticationAttemptPolicy attemptPolicy = new(
            options.Value.MultiFactor.ManagementMaximumAttempts,
            TimeSpan.FromMinutes(options.Value.MultiFactor.ManagementAttemptWindowMinutes));
        AuthenticationAttemptLease? attemptLease = await attemptLimiter.TryAcquireAsync(
                member.ScopeId,
                AuthenticationAttemptPurposes.MultiFactorManagement,
                limiterTarget,
                attemptCheckedAtUtc,
                attemptPolicy,
                cancellationToken).ConfigureAwait(false);
        if (attemptLease is null)
        {
            return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Invalid);
        }

        DateTimeOffset nowUtc = this.Clock.UtcNow;

        refreshProof = member.VerifySessionRefreshTokenAndHandleReuse(
            new MemberSessionId(command.SessionId),
            candidateRefreshTokenHashes,
            this.IdGenerator.NewId(),
            nowUtc);
        if (refreshProof.IsFailure)
        {
            return refreshProof.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.ReuseDetected)
                : Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(refreshProof.Error);
        }

        Result<SessionAuthenticationEvidence> factor = multiFactorAuthentication.VerifyFactor(
            authenticator,
            new SessionAuthenticationEvidence(
                refreshProof.Value.AuthenticationContextReference,
                refreshProof.Value.AuthenticationMethodReferences,
                refreshProof.Value.AuthenticatedAtUtc),
            command.CodeType,
            command.Code,
            nowUtc);
        if (factor.IsFailure)
        {
            if (factor.Error == AuthApplicationErrors.MultiFactorProviderUnavailable)
            {
                return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(factor.Error);
            }

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

        DateTimeOffset completedAtUtc = this.Clock.UtcNow;
        refreshProof = member.VerifySessionRefreshTokenAndHandleReuse(
            new MemberSessionId(command.SessionId),
            candidateRefreshTokenHashes,
            this.IdGenerator.NewId(),
            completedAtUtc);
        if (refreshProof.IsFailure)
        {
            return refreshProof.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.ReuseDetected)
                : Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(refreshProof.Error);
        }

        string refreshToken = this.GenerateRefreshToken();
        Result<MemberSession> refreshed = member.RefreshSession(
            refreshProof.Value.Id,
            candidateRefreshTokenHashes,
            this.TokenHashingService.HashRefreshToken(refreshToken),
            completedAtUtc.AddDays(options.Value.RefreshTokenLifetimeDays),
            this.IdGenerator.NewId(),
            completedAtUtc);
        if (refreshed.IsFailure)
        {
            return refreshed.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.ReuseDetected)
                : Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(refreshed.Error);
        }

        IReadOnlyList<RecoveryCodeMaterial> recoveryCodes = multiFactorAuthentication.GenerateRecoveryCodes();
        Result regenerated = authenticator.RegenerateRecoveryCodes(
            multiFactorAuthentication.CreateRecoveryCodeRegistrations(recoveryCodes),
            completedAtUtc);
        if (regenerated.IsFailure)
        {
            return Result.Failure<MultiFactorRecoveryCodeRegenerationCompletion>(regenerated.Error);
        }

        await failureAttemptRepository.ClearBeforeAsync(
            memberId,
            MemberMultiFactorFailureAttempt.ManagementPurpose,
            attemptLease.Value.AcquiredAtUtc,
            cancellationToken).ConfigureAwait(false);
        await attemptLimiter.RecordSuccessAsync(
            member.ScopeId,
            AuthenticationAttemptPurposes.MultiFactorManagement,
            limiterTarget,
            attemptLease.Value,
            cancellationToken).ConfigureAwait(false);
        return Result.Success(MultiFactorRecoveryCodeRegenerationCompletion.Completed(
            new MultiFactorRecoveryCodesResponse(
                this.CreateAccessToken(member, refreshed.Value),
                refreshToken,
                recoveryCodes.Select(code => code.Plaintext).ToArray())));
    }
}
