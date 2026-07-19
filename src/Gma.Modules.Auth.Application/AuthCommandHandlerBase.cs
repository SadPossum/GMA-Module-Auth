namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;

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

    protected (MemberSessionId SessionId, string RefreshToken, string RefreshTokenHash, DateTimeOffset ExpiresAtUtc)
        CreateSessionTokens(TimeSpan refreshTokenLifetime)
    {
        MemberSessionId sessionId = new(this.IdGenerator.NewId());
        string refreshToken = tokenService.GenerateRefreshToken();
        string refreshTokenHash = refreshTokenHashingService.HashRefreshToken(refreshToken);
        DateTimeOffset expiresAtUtc = this.Clock.UtcNow.Add(refreshTokenLifetime);

        return (sessionId, refreshToken, refreshTokenHash, expiresAtUtc);
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
