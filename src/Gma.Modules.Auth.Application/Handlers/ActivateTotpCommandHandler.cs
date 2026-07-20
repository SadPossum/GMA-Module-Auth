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

internal sealed class ActivateTotpCommandHandler(
    IMemberRepository memberRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    MultiFactorAuthenticationService multiFactorAuthentication,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<ActivateTotpCommand, RefreshTokenBoundCompletion<TotpActivationResponse>>
{
    public async Task<Result<RefreshTokenBoundCompletion<TotpActivationResponse>>> HandleAsync(
        ActivateTotpCommand command,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null ||
            (scopeContext.IsEnabled && !string.Equals(scopeContext.ScopeId, member.ScopeId, StringComparison.Ordinal)))
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(AuthDomainErrors.MemberNotFound);
        }

        DateTimeOffset authorizationCheckedAtUtc = this.Clock.UtcNow;
        Result<MemberSession> freshSession = MemberSecurityAuthorization.RequireFreshSession(
            member,
            command.SessionId,
            authorizationCheckedAtUtc,
            TimeSpan.FromMinutes(options.Value.MultiFactor.SensitiveSessionFreshnessMinutes));
        if (freshSession.IsFailure ||
            string.Equals(
                freshSession.Value.AuthenticationContextReference,
                AuthenticationContextReferences.Legacy,
                StringComparison.Ordinal))
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(
                AuthApplicationErrors.FreshAuthenticationRequired);
        }

        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(memberId, cancellationToken)
            .ConfigureAwait(false);
        if (authenticator is null)
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(
                AuthApplicationErrors.TotpEnrollmentInvalid);
        }

        DateTimeOffset nowUtc = this.Clock.UtcNow;
        freshSession = MemberSecurityAuthorization.RequireFreshSession(
            member,
            command.SessionId,
            nowUtc,
            TimeSpan.FromMinutes(options.Value.MultiFactor.SensitiveSessionFreshnessMinutes));
        if (freshSession.IsFailure ||
            string.Equals(
                freshSession.Value.AuthenticationContextReference,
                AuthenticationContextReferences.Legacy,
                StringComparison.Ordinal))
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(
                AuthApplicationErrors.FreshAuthenticationRequired);
        }

        Result<long> verification = multiFactorAuthentication.VerifyPendingTotp(
            authenticator,
            command.Code,
            nowUtc);
        if (verification.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(verification.Error);
        }

        IReadOnlyList<RecoveryCodeMaterial> recoveryCodes = multiFactorAuthentication.GenerateRecoveryCodes();
        SessionAuthenticationEvidence primaryEvidence = CreatePrimaryEvidence(
            freshSession.Value.AuthenticationMethod,
            nowUtc);
        string refreshToken = this.GenerateRefreshToken();
        Result<MemberSession> reauthenticated = member.ReauthenticateSession(
            freshSession.Value.Id,
            this.TokenHashingService.GetCandidateHashes(command.RefreshToken),
            this.TokenHashingService.HashRefreshToken(refreshToken),
            nowUtc.AddDays(options.Value.RefreshTokenLifetimeDays),
            nowUtc.AddDays(options.Value.SessionAbsoluteLifetimeDays),
            SessionAuthenticationEvidence.CompleteWithTotp(primaryEvidence, nowUtc),
            this.IdGenerator.NewId(),
            nowUtc);
        if (reauthenticated.IsFailure)
        {
            return reauthenticated.Error == AuthApplicationErrors.RefreshTokenReused
                ? Result.Success(RefreshTokenBoundCompletion.ReuseDetected<TotpActivationResponse>())
                : Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(reauthenticated.Error);
        }

        Result activated = authenticator.Activate(
            verification.Value,
            multiFactorAuthentication.CreateRecoveryCodeRegistrations(recoveryCodes),
            nowUtc);
        if (activated.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(activated.Error);
        }

        Result methodChanged = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Totp,
            MemberAuthenticationMethodChange.Added,
            this.IdGenerator.NewId(),
            nowUtc);
        if (methodChanged.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<TotpActivationResponse>>(methodChanged.Error);
        }

        return Result.Success(RefreshTokenBoundCompletion.Completed(
            new TotpActivationResponse(
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
