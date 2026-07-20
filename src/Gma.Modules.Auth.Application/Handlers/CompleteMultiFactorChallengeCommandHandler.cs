namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

internal sealed class CompleteMultiFactorChallengeCommandHandler(
    IMemberAuthenticationChallengeRepository challengeRepository,
    IMemberTotpAuthenticatorRepository authenticatorRepository,
    IMemberRepository memberRepository,
    MultiFactorAuthenticationService multiFactorAuthentication,
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    IOptions<AuthApplicationOptions> options,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, refreshTokenHashingService, clock, idGenerator),
        ICommandHandler<CompleteMultiFactorChallengeCommand, MultiFactorChallengeCompletion>
{
    public async Task<Result<MultiFactorChallengeCompletion>> HandleAsync(
        CompleteMultiFactorChallengeCommand command,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<string> candidateHashes = multiFactorAuthentication
            .GetCandidateChallengeTokenHashes(command.ChallengeToken);
        MemberAuthenticationChallenge? challenge = await challengeRepository
            .GetByTokenHashesAsync(candidateHashes, cancellationToken)
            .ConfigureAwait(false);
        DateTimeOffset challengeCheckedAtUtc = this.Clock.UtcNow;
        if (challenge is null || !challenge.IsActiveAt(challengeCheckedAtUtc))
        {
            return Result.Failure<MultiFactorChallengeCompletion>(AuthApplicationErrors.MultiFactorChallengeInvalid);
        }

        Member? member = await memberRepository
            .GetByIdAsync(challenge.MemberId, cancellationToken)
            .ConfigureAwait(false);
        MemberTotpAuthenticator? authenticator = await authenticatorRepository
            .GetByMemberAsync(challenge.MemberId, cancellationToken)
            .ConfigureAwait(false);
        DateTimeOffset nowUtc = this.Clock.UtcNow;
        if (!challenge.IsActiveAt(nowUtc))
        {
            return Result.Failure<MultiFactorChallengeCompletion>(AuthApplicationErrors.MultiFactorChallengeInvalid);
        }

        if (member is null || authenticator is null || !authenticator.IsActive)
        {
            challenge.RecordFailure(nowUtc);
            return Result.Success(MultiFactorChallengeCompletion.Invalid);
        }

        Result<SessionAuthenticationEvidence> factor = multiFactorAuthentication.VerifyFactor(
            authenticator,
            challenge.PrimaryEvidence,
            command.CodeType,
            command.Code,
            nowUtc);
        if (factor.IsFailure)
        {
            if (factor.Error == AuthApplicationErrors.MultiFactorProviderUnavailable)
            {
                return Result.Failure<MultiFactorChallengeCompletion>(factor.Error);
            }

            challenge.RecordFailure(nowUtc);
            return Result.Success(MultiFactorChallengeCompletion.Invalid);
        }

        var tokens = this.CreateSessionTokens(
            nowUtc,
            TimeSpan.FromDays(options.Value.RefreshTokenLifetimeDays),
            TimeSpan.FromDays(options.Value.SessionAbsoluteLifetimeDays));
        Result<MemberSession> session = member.StartSession(
            tokens.SessionId,
            tokens.RefreshTokenHash,
            tokens.ExpiresAtUtc,
            nowUtc,
            challenge.PrimaryAuthenticationMethod,
            factor.Value,
            options.Value.MaximumActiveSessionsPerMember,
            tokens.AbsoluteExpiresAtUtc);
        if (session.IsFailure)
        {
            return Result.Failure<MultiFactorChallengeCompletion>(session.Error);
        }

        string matchedHash = candidateHashes.First(challenge.MatchesTokenHash);
        Result consumed = challenge.Consume(matchedHash, nowUtc);
        if (consumed.IsFailure)
        {
            return Result.Failure<MultiFactorChallengeCompletion>(consumed.Error);
        }

        Result authenticated = member.RecordAuthentication(
            tokens.SessionId,
            this.IdGenerator.NewId(),
            nowUtc,
            challenge.IpAddress,
            challenge.UserAgent);
        if (authenticated.IsFailure)
        {
            return Result.Failure<MultiFactorChallengeCompletion>(authenticated.Error);
        }

        return Result.Success(MultiFactorChallengeCompletion.Authenticated(
            new AuthTokensResponse(this.CreateAccessToken(member, session.Value), tokens.RefreshToken)));
    }
}
