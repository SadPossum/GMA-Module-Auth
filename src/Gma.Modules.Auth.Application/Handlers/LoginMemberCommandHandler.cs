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

internal sealed class LoginMemberCommandHandler(
    IMemberRepository memberRepository,
    IPasswordHashingService passwordHashingService,
    PasswordProofService passwordProofService,
    MultiFactorAuthenticationService multiFactorAuthentication,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<LoginMemberCommand, PrimaryAuthenticationResult>
{
    public async Task<Result<PrimaryAuthenticationResult>> HandleAsync(
        LoginMemberCommand command,
        CancellationToken cancellationToken)
    {
        string scopeId = scopeContext.ScopeId ?? string.Empty;
        string attemptTarget = MemberUsername.Normalize(command.Username);

        Member? member = await memberRepository.GetByUsernameAsync(command.Username, cancellationToken).ConfigureAwait(false);
        string? passwordHash = member is not null && member.HasActiveUsername(command.Username)
            ? member.PasswordHash
            : null;
        PasswordVerificationOutcome passwordVerification = await passwordProofService.VerifyAsync(
            scopeId,
            AuthenticationAttemptPurposes.PasswordLogin,
            attemptTarget,
            passwordHash,
            command.Password,
            this.Clock.UtcNow,
            cancellationToken).ConfigureAwait(false);
        if (passwordVerification == PasswordVerificationOutcome.Unknown)
        {
            return Result.Failure<PrimaryAuthenticationResult>(AuthDomainErrors.CredentialsNotValid);
        }

        if (member is null)
        {
            return Result.Failure<PrimaryAuthenticationResult>(AuthDomainErrors.CredentialsNotValid);
        }

        if (passwordVerification == PasswordVerificationOutcome.SuccessRehashNeeded)
        {
            Result rehashResult = member.ResetPassword(passwordHashingService.HashPassword(command.Password));
            if (rehashResult.IsFailure)
            {
                return Result.Failure<PrimaryAuthenticationResult>(rehashResult.Error);
            }
        }

        DateTimeOffset nowUtc = this.Clock.UtcNow;
        SessionAuthenticationEvidence primaryEvidence = SessionAuthenticationEvidence.Password(nowUtc);
        Result<MultiFactorChallengeRequirement> challenge = await multiFactorAuthentication
            .CreateChallengeIfRequiredAsync(
                member,
                MemberAuthenticationMethods.Password,
                primaryEvidence,
                AuthenticationClientContext.NormalizeIpAddress(command.IpAddress),
                AuthenticationClientContext.NormalizeUserAgent(command.UserAgent),
                cancellationToken)
            .ConfigureAwait(false);
        if (challenge.IsFailure)
        {
            return Result.Failure<PrimaryAuthenticationResult>(challenge.Error);
        }

        if (challenge.Value.IsRequired)
        {
            return Result.Success(PrimaryAuthenticationResult.Challenge(challenge.Value.Challenge!));
        }

        var tokens = this.CreateSessionTokens(
            TimeSpan.FromDays(options.Value.RefreshTokenLifetimeDays),
            TimeSpan.FromDays(options.Value.SessionAbsoluteLifetimeDays));
        Result<MemberSession> startSessionResult = member.StartSession(
            tokens.SessionId,
            tokens.RefreshTokenHash,
            tokens.ExpiresAtUtc,
            this.Clock.UtcNow,
            authenticationEvidence: primaryEvidence,
            maximumActiveSessions: options.Value.MaximumActiveSessionsPerMember,
            absoluteExpiresAtUtc: tokens.AbsoluteExpiresAtUtc);

        if (startSessionResult.IsFailure)
        {
            return Result.Failure<PrimaryAuthenticationResult>(startSessionResult.Error);
        }

        Result authenticated = member.RecordAuthentication(
            tokens.SessionId,
            this.IdGenerator.NewId(),
            this.Clock.UtcNow,
            AuthenticationClientContext.NormalizeIpAddress(command.IpAddress),
            AuthenticationClientContext.NormalizeUserAgent(command.UserAgent));
        if (authenticated.IsFailure)
        {
            return Result.Failure<PrimaryAuthenticationResult>(authenticated.Error);
        }

        string accessToken = this.CreateAccessToken(member, startSessionResult.Value);
        return Result.Success(PrimaryAuthenticationResult.Authenticated(
            new AuthTokensResponse(accessToken, tokens.RefreshToken)));
    }
}
