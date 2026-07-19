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

internal sealed class StepUpWithPasswordCommandHandler(
    IMemberRepository memberRepository,
    IPasswordHashingService passwordHashingService,
    PasswordProofService passwordProofService,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<StepUpWithPasswordCommand, AuthTokensResponse>
{
    public async Task<Result<AuthTokensResponse>> HandleAsync(
        StepUpWithPasswordCommand command,
        CancellationToken cancellationToken)
    {
        MemberId memberId = new(command.MemberId);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null ||
            (scopeContext.IsEnabled &&
             !string.Equals(scopeContext.ScopeId, member.ScopeId, StringComparison.Ordinal)))
        {
            return Result.Failure<AuthTokensResponse>(AuthDomainErrors.CredentialsNotValid);
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
            return Result.Failure<AuthTokensResponse>(AuthDomainErrors.CredentialsNotValid);
        }

        string refreshToken = this.GenerateRefreshToken();
        string newRefreshTokenHash = this.TokenHashingService.HashRefreshToken(refreshToken);
        IReadOnlyList<string> candidateHashes = this.TokenHashingService.GetCandidateHashes(command.RefreshToken);
        DateTimeOffset nowUtc = this.Clock.UtcNow;
        Result<MemberSession> reauthenticated = member.ReauthenticateSession(
            new MemberSessionId(command.SessionId),
            candidateHashes,
            newRefreshTokenHash,
            nowUtc.AddDays(options.Value.RefreshTokenLifetimeDays),
            SessionAuthenticationEvidence.Password(nowUtc),
            this.IdGenerator.NewId(),
            nowUtc);
        if (reauthenticated.IsFailure)
        {
            return Result.Failure<AuthTokensResponse>(reauthenticated.Error);
        }

        if (passwordVerification == PasswordVerificationOutcome.SuccessRehashNeeded)
        {
            Result rehashResult = member.ResetPassword(passwordHashingService.HashPassword(command.Password));
            if (rehashResult.IsFailure)
            {
                return Result.Failure<AuthTokensResponse>(rehashResult.Error);
            }
        }

        string accessToken = this.CreateAccessToken(member, reauthenticated.Value);
        return Result.Success(new AuthTokensResponse(accessToken, refreshToken));
    }
}
