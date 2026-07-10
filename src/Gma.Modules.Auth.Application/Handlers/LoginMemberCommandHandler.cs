namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.Extensions.Options;
using Gma.Framework.Cqrs;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Results;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Security;

internal sealed class LoginMemberCommandHandler(
    IMemberRepository memberRepository,
    IPasswordHashingService passwordHashingService,
    IAuthenticationAttemptLimiter attemptLimiter,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<LoginMemberCommand, AuthTokensResponse>
{
    public async Task<Result<AuthTokensResponse>> HandleAsync(
        LoginMemberCommand command,
        CancellationToken cancellationToken)
    {
        string scopeId = scopeContext.ScopeId ?? string.Empty;
        if (!attemptLimiter.IsAllowed(scopeId, command.Username, this.Clock.UtcNow))
        {
            return Result.Failure<AuthTokensResponse>(AuthDomainErrors.CredentialsNotValid);
        }

        Member? member = await memberRepository.GetByUsernameAsync(command.Username, cancellationToken).ConfigureAwait(false);

        if (member is null || !member.HasActiveUsername(command.Username))
        {
            attemptLimiter.RecordFailure(scopeId, command.Username, this.Clock.UtcNow);
            return Result.Failure<AuthTokensResponse>(AuthDomainErrors.CredentialsNotValid);
        }

        PasswordVerificationOutcome passwordVerification = passwordHashingService.VerifyPassword(
            member.PasswordHash,
            command.Password);
        if (passwordVerification == PasswordVerificationOutcome.Unknown)
        {
            attemptLimiter.RecordFailure(scopeId, command.Username, this.Clock.UtcNow);
            return Result.Failure<AuthTokensResponse>(AuthDomainErrors.CredentialsNotValid);
        }

        attemptLimiter.RecordSuccess(scopeId, command.Username);

        if (passwordVerification == PasswordVerificationOutcome.SuccessRehashNeeded)
        {
            Result rehashResult = member.ResetPassword(passwordHashingService.HashPassword(command.Password));
            if (rehashResult.IsFailure)
            {
                return Result.Failure<AuthTokensResponse>(rehashResult.Error);
            }
        }

        var tokens = this.CreateTokens(member.Id, member.ScopeId, TimeSpan.FromDays(options.Value.RefreshTokenLifetimeDays));
        Result startSessionResult = member.StartSession(tokens.SessionId, tokens.RefreshTokenHash, tokens.ExpiresAtUtc, this.Clock.UtcNow);

        if (startSessionResult.IsFailure)
        {
            return Result.Failure<AuthTokensResponse>(startSessionResult.Error);
        }

        return Result.Success(new AuthTokensResponse(tokens.AccessToken, tokens.RefreshToken));
    }
}
