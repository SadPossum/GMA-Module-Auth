namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Framework.Results;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Errors;

internal abstract class AuthCommandHandlerBase(
    ITokenService tokenService,
    IRefreshTokenHashingService refreshTokenHashingService,
    ISystemClock clock,
    IIdGenerator idGenerator)
{
    protected ISystemClock Clock => clock;
    protected IIdGenerator IdGenerator => idGenerator;
    protected IRefreshTokenHashingService TokenHashingService => refreshTokenHashingService;
    protected string GenerateRefreshToken() => tokenService.GenerateRefreshToken();

    protected Result<SessionTokenRotation> RotateSessionRefreshToken(
        Member member,
        MemberSessionId sessionId,
        string presentedRefreshToken,
        DateTimeOffset nowUtc,
        TimeSpan refreshTokenLifetime,
        TimeSpan absoluteSessionLifetime,
        SessionAuthenticationEvidence? reauthenticationEvidence = null)
    {
        string refreshToken = tokenService.GenerateRefreshToken();
        string refreshTokenHash = refreshTokenHashingService.HashRefreshToken(refreshToken);
        IReadOnlyList<string> candidateHashes = refreshTokenHashingService.GetCandidateHashes(presentedRefreshToken);
        Result<MemberSession> session = reauthenticationEvidence is null
            ? member.RefreshSession(
                sessionId,
                candidateHashes,
                refreshTokenHash,
                nowUtc.Add(refreshTokenLifetime),
                this.IdGenerator.NewId(),
                nowUtc)
            : member.ReauthenticateSession(
                sessionId,
                candidateHashes,
                refreshTokenHash,
                nowUtc.Add(refreshTokenLifetime),
                nowUtc.Add(absoluteSessionLifetime),
                reauthenticationEvidence,
                this.IdGenerator.NewId(),
                nowUtc);

        return session.IsSuccess
            ? Result.Success(new SessionTokenRotation(session.Value, refreshToken))
            : Result.Failure<SessionTokenRotation>(session.Error);
    }

    protected static Result<RefreshTokenBoundCompletion<AuthTokensResponse>> ToTokenRotationFailure(Error error) =>
        error == AuthApplicationErrors.RefreshTokenReused
            ? Result.Success(RefreshTokenBoundCompletion.ReuseDetected<AuthTokensResponse>())
            : Result.Failure<RefreshTokenBoundCompletion<AuthTokensResponse>>(error);

    protected (
        MemberSessionId SessionId,
        string RefreshToken,
        string RefreshTokenHash,
        DateTimeOffset ExpiresAtUtc,
        DateTimeOffset AbsoluteExpiresAtUtc)
        CreateSessionTokens(TimeSpan refreshTokenLifetime, TimeSpan absoluteSessionLifetime)
    {
        MemberSessionId sessionId = new(this.IdGenerator.NewId());
        string refreshToken = tokenService.GenerateRefreshToken();
        string refreshTokenHash = refreshTokenHashingService.HashRefreshToken(refreshToken);
        DateTimeOffset nowUtc = this.Clock.UtcNow;
        DateTimeOffset expiresAtUtc = nowUtc.Add(refreshTokenLifetime);
        DateTimeOffset absoluteExpiresAtUtc = nowUtc.Add(absoluteSessionLifetime);

        return (sessionId, refreshToken, refreshTokenHash, expiresAtUtc, absoluteExpiresAtUtc);
    }

    protected string CreateAccessToken(Member member, MemberSession session) =>
        tokenService.GenerateAccessToken(new AccessTokenClaims(
            member.Id,
            member.ScopeId,
            session.Id,
            new SessionAuthenticationEvidence(
                session.AuthenticationContextReference,
                session.AuthenticationMethodReferences,
                session.AuthenticatedAtUtc)));
}

internal sealed record SessionTokenRotation(MemberSession Session, string RefreshToken);
