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

internal sealed class SetMemberPasswordCommandHandler(
    IMemberRepository memberRepository,
    IPasswordHashingService passwordHashingService,
    IPasswordBlocklist passwordBlocklist,
    PasswordProofService passwordProofService,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    ISystemClock clock,
    IIdGenerator idGenerator,
    IOptions<AuthApplicationOptions> options)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<SetMemberPasswordCommand, RefreshTokenBoundCompletion<AuthTokensResponse>>
{
    public async Task<Result<RefreshTokenBoundCompletion<AuthTokensResponse>>> HandleAsync(
        SetMemberPasswordCommand command,
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

        if (member.HasPassword)
        {
            PasswordVerificationOutcome password = await passwordProofService.VerifyAsync(
                member.ScopeId,
                AuthenticationAttemptPurposes.PasswordChange,
                command.MemberId.ToString("D", System.Globalization.CultureInfo.InvariantCulture),
                member.PasswordHash,
                command.CurrentPassword ?? string.Empty,
                authorizationCheckedAtUtc,
                cancellationToken).ConfigureAwait(false);
            if (password == PasswordVerificationOutcome.Unknown)
            {
                return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(
                    AuthDomainErrors.CredentialsNotValid);
            }
        }

        if (await passwordBlocklist.IsBlockedAsync(command.NewPassword, cancellationToken).ConfigureAwait(false))
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(
                AuthApplicationErrors.PasswordBlocked);
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

        bool hadPassword = member.HasPassword;
        Result<SessionTokenRotation> rotated = this.RotateSessionRefreshToken(
            member,
            freshSession.Value.Id,
            command.RefreshToken,
            nowUtc,
            TimeSpan.FromDays(options.Value.RefreshTokenLifetimeDays),
            TimeSpan.FromDays(options.Value.SessionAbsoluteLifetimeDays),
            hadPassword ? SessionAuthenticationEvidence.Password(nowUtc) : null);
        if (rotated.IsFailure)
        {
            return ToTokenRotationFailure(rotated.Error);
        }

        Result result = member.ResetPassword(passwordHashingService.HashPassword(command.NewPassword));
        if (result.IsFailure)
        {
            return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(result.Error);
        }

        if (hadPassword)
        {
            Result<int> revoked = member.RevokeSessionsExcept(
                rotated.Value.Session.Id,
                this.IdGenerator.NewId(),
                nowUtc);
            if (revoked.IsFailure)
            {
                return Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(revoked.Error);
            }
        }

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.Password,
            hadPassword ? MemberAuthenticationMethodChange.Updated : MemberAuthenticationMethodChange.Added,
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
