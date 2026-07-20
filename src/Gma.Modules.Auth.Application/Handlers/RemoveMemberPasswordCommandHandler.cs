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

internal sealed class RemoveMemberPasswordCommandHandler(
    IMemberRepository memberRepository,
    PasswordProofService passwordProofService,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IOptions<AuthApplicationOptions> options)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<RemoveMemberPasswordCommand, RefreshTokenBoundCompletion<AuthTokensResponse>>
{
    public async Task<Result<RefreshTokenBoundCompletion<AuthTokensResponse>>> HandleAsync(
        RemoveMemberPasswordCommand command,
        CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByIdAsync(new MemberId(command.MemberId), cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(AuthDomainErrors.MemberNotFound);
        }

        DateTimeOffset authorizationCheckedAtUtc = this.Clock.UtcNow;
        Result<MemberSession> freshSession = MemberSecurityAuthorization.RequireFreshSession(
            member,
            command.SessionId,
            authorizationCheckedAtUtc,
            TimeSpan.FromMinutes(options.Value.ExternalLinkSessionFreshnessMinutes));
        if (freshSession.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(freshSession.Error);
        }

        PasswordVerificationOutcome password = await passwordProofService.VerifyAsync(
            member.ScopeId,
            AuthenticationAttemptPurposes.PasswordRemoval,
            command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture),
            member.PasswordHash,
            command.CurrentPassword,
            authorizationCheckedAtUtc,
            cancellationToken).ConfigureAwait(false);
        if (password == PasswordVerificationOutcome.Unknown)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(
                AuthDomainErrors.CredentialsNotValid);
        }

        if (member.ExternalIdentities.Count == 0)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(
                AuthDomainErrors.AuthenticationMethodRequired);
        }

        DateTimeOffset nowUtc = this.Clock.UtcNow;
        freshSession = MemberSecurityAuthorization.RequireFreshSession(
            member,
            command.SessionId,
            nowUtc,
            TimeSpan.FromMinutes(options.Value.ExternalLinkSessionFreshnessMinutes));
        if (freshSession.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(freshSession.Error);
        }

        Result<SessionTokenRotation> rotated = this.RotateSessionRefreshToken(
            member,
            freshSession.Value.Id,
            command.RefreshToken,
            nowUtc,
            TimeSpan.FromDays(options.Value.RefreshTokenLifetimeDays),
            TimeSpan.FromDays(options.Value.SessionAbsoluteLifetimeDays),
            SessionAuthenticationEvidence.Password(nowUtc));
        if (rotated.IsFailure)
        {
            return ToTokenRotationFailure(rotated.Error);
        }

        Result result = member.RemovePassword();
        if (result.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(result.Error);
        }

        Result<int> revoked = member.RevokeSessionsAuthenticatedWith(
            MemberAuthenticationMethods.Password,
            rotated.Value.Session.Id,
            this.IdGenerator.NewId(),
            nowUtc);
        if (revoked.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(revoked.Error);
        }

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Password,
            MemberAuthenticationMethodChange.Removed,
            this.IdGenerator.NewId(),
            nowUtc);
        if (changed.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(changed.Error);
        }

        return Result.Success(RefreshTokenBoundCompletion.Completed(
            new AuthTokensResponse(
                this.CreateAccessToken(member, rotated.Value.Session),
                rotated.Value.RefreshToken)));
    }
}
