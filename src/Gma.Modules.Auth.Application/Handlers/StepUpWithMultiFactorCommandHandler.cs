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

internal sealed class StepUpWithMultiFactorCommandHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    IMemberMultiFactorFailureAttemptRepository failureAttemptRepository,
    IPasswordHashingService passwordHashingService,
    PasswordProofService passwordProofService,
    MultiFactorAuthenticationService multiFactorAuthentication,
    IAuthenticationAttemptLimiter attemptLimiter,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<StepUpWithMultiFactorCommand, MultiFactorStepUpCompletion>
{
    public async Task<Result<MultiFactorStepUpCompletion>> HandleAsync(
        StepUpWithMultiFactorCommand command,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null ||
            (scopeContext.IsEnabled && !string.Equals(scopeContext.ScopeId, member.ScopeId, StringComparison.Ordinal)))
        {
            return Result.Failure<MultiFactorStepUpCompletion>(AuthDomainErrors.CredentialsNotValid);
        }

        DateTimeOffset refreshCheckedAtUtc = this.Clock.UtcNow;
        IReadOnlyList<string> candidateRefreshTokenHashes =
            this.TokenHashingService.GetCandidateHashes(command.RefreshToken);
        Result<MemberSession> refreshProof = member.VerifySessionRefreshTokenAndHandleReuse(
            new MemberSessionId(command.SessionId),
            candidateRefreshTokenHashes,
            this.IdGenerator.NewId(),
            refreshCheckedAtUtc);
        if (refreshProof.IsFailure)
        {
            return refreshProof.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(MultiFactorStepUpCompletion.ReuseDetected)
                : Result.Failure<MultiFactorStepUpCompletion>(refreshProof.Error);
        }

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (authenticator is null || !authenticator.IsActive)
        {
            return Result.Failure<MultiFactorStepUpCompletion>(AuthApplicationErrors.TotpAuthenticatorNotActive);
        }

        if (member.PasswordHash is null)
        {
            return Result.Failure<MultiFactorStepUpCompletion>(AuthApplicationErrors.PasswordNotConfigured);
        }

        PasswordVerificationOutcome passwordVerification = await passwordProofService.VerifyAsync(
            member.ScopeId,
            AuthenticationAttemptPurposes.PasswordStepUp,
            command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture),
            member.PasswordHash,
            command.Password,
            this.Clock.UtcNow,
            cancellationToken).ConfigureAwait(false);
        if (passwordVerification == PasswordVerificationOutcome.Unknown)
        {
            return Result.Success(MultiFactorStepUpCompletion.Invalid);
        }

        DateTimeOffset attemptCheckedAtUtc = this.Clock.UtcNow;
        string limiterTarget = command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture);
        int recentFailureCount = await failureAttemptRepository.CountSinceAsync(
            memberId,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            attemptCheckedAtUtc.AddMinutes(-options.Value.MultiFactor.ManagementAttemptWindowMinutes),
            cancellationToken).ConfigureAwait(false);
        if (recentFailureCount >= options.Value.MultiFactor.ManagementMaximumAttempts)
        {
            return Result.Success(MultiFactorStepUpCompletion.Invalid);
        }

        if (command.CodeType == MultiFactorCodeType.Totp && !multiFactorAuthentication.TotpProviderAvailable)
        {
            return Result.Failure<MultiFactorStepUpCompletion>(
                AuthApplicationErrors.MultiFactorProviderUnavailable);
        }

        AuthenticationAttemptPolicy attemptPolicy = new(
            options.Value.MultiFactor.ManagementMaximumAttempts,
            TimeSpan.FromMinutes(options.Value.MultiFactor.ManagementAttemptWindowMinutes));
        AuthenticationAttemptLease? attemptLease = await attemptLimiter.TryAcquireAsync(
                member.ScopeId,
                AuthenticationAttemptPurposes.MultiFactorStepUp,
                limiterTarget,
                attemptCheckedAtUtc,
                attemptPolicy,
                cancellationToken).ConfigureAwait(false);
        if (attemptLease is null)
        {
            return Result.Success(MultiFactorStepUpCompletion.Invalid);
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
                ? Result.Success(MultiFactorStepUpCompletion.ReuseDetected)
                : Result.Failure<MultiFactorStepUpCompletion>(refreshProof.Error);
        }

        Result<SessionAuthenticationEvidence> factor = multiFactorAuthentication.VerifyFactor(
            authenticator,
            SessionAuthenticationEvidence.Password(nowUtc),
            command.CodeType,
            command.Code,
            nowUtc);
        if (factor.IsFailure)
        {
            if (factor.Error == AuthApplicationErrors.MultiFactorProviderUnavailable)
            {
                return Result.Failure<MultiFactorStepUpCompletion>(factor.Error);
            }

            Result<MemberMultiFactorFailureAttempt> failedAttempt = MemberMultiFactorFailureAttempt.Create(
                new MemberMultiFactorFailureAttemptId(this.IdGenerator.NewId()),
                memberId,
                member.ScopeId,
                MemberMultiFactorFailureAttempt.StepUpPurpose,
                nowUtc);
            if (failedAttempt.IsFailure)
            {
                return Result.Failure<MultiFactorStepUpCompletion>(failedAttempt.Error);
            }

            await failureAttemptRepository.AddAsync(failedAttempt.Value, cancellationToken).ConfigureAwait(false);
            return Result.Success(MultiFactorStepUpCompletion.Invalid);
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
                ? Result.Success(MultiFactorStepUpCompletion.ReuseDetected)
                : Result.Failure<MultiFactorStepUpCompletion>(refreshProof.Error);
        }

        SessionAuthenticationEvidence completedEvidence = command.CodeType == MultiFactorCodeType.Totp
            ? SessionAuthenticationEvidence.CompleteWithTotp(
                SessionAuthenticationEvidence.Password(completedAtUtc),
                completedAtUtc)
            : SessionAuthenticationEvidence.CompleteWithRecoveryCode(
                SessionAuthenticationEvidence.Password(completedAtUtc),
                completedAtUtc);
        string refreshToken = this.GenerateRefreshToken();
        Result<MemberSession> reauthenticated = member.ReauthenticateSession(
            refreshProof.Value.Id,
            candidateRefreshTokenHashes,
            this.TokenHashingService.HashRefreshToken(refreshToken),
            completedAtUtc.AddDays(options.Value.RefreshTokenLifetimeDays),
            completedAtUtc.AddDays(options.Value.SessionAbsoluteLifetimeDays),
            completedEvidence,
            this.IdGenerator.NewId(),
            completedAtUtc);
        if (reauthenticated.IsFailure)
        {
            return reauthenticated.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(MultiFactorStepUpCompletion.ReuseDetected)
                : Result.Failure<MultiFactorStepUpCompletion>(reauthenticated.Error);
        }

        if (passwordVerification == PasswordVerificationOutcome.SuccessRehashNeeded)
        {
            Result rehashResult = member.ResetPassword(passwordHashingService.HashPassword(command.Password));
            if (rehashResult.IsFailure)
            {
                return Result.Failure<MultiFactorStepUpCompletion>(rehashResult.Error);
            }
        }

        await failureAttemptRepository.ClearBeforeAsync(
            memberId,
            MemberMultiFactorFailureAttempt.StepUpPurpose,
            attemptLease.Value.AcquiredAtUtc,
            cancellationToken).ConfigureAwait(false);
        await attemptLimiter.RecordSuccessAsync(
            member.ScopeId,
            AuthenticationAttemptPurposes.MultiFactorStepUp,
            limiterTarget,
            attemptLease.Value,
            cancellationToken).ConfigureAwait(false);
        return Result.Success(MultiFactorStepUpCompletion.Completed(
            new AuthTokensResponse(this.CreateAccessToken(member, reauthenticated.Value), refreshToken)));
    }
}
