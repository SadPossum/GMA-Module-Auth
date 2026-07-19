namespace Gma.Modules.Auth.Domain.Services;

using Gma.Framework.Naming;
using Gma.Modules.Auth.Domain.ValueObjects;

public interface ITokenService
{
    string GenerateAccessToken(AccessTokenClaims claims);
    string GenerateRefreshToken();
    MemberId? GetMemberId(string accessToken, bool validateLifetime);
    AccessTokenClaims? GetAccessTokenClaims(string accessToken, bool validateLifetime);
}

public sealed record AccessTokenClaims
{
    public AccessTokenClaims(
        MemberId memberId,
        string scopeId,
        MemberSessionId sessionId,
        SessionAuthenticationEvidence authenticationEvidence)
    {
        if (memberId.Value == Guid.Empty)
        {
            throw new ArgumentException("Member id is required.", nameof(memberId));
        }

        if (sessionId.Value == Guid.Empty)
        {
            throw new ArgumentException("Member session id is required.", nameof(sessionId));
        }

        this.MemberId = memberId;
        this.ScopeId = ScopeIds.Normalize(scopeId);
        this.SessionId = sessionId;
        this.AuthenticationEvidence = authenticationEvidence ??
            throw new ArgumentNullException(nameof(authenticationEvidence));
    }

    public MemberId MemberId { get; }
    public string ScopeId { get; }
    public MemberSessionId SessionId { get; }
    public SessionAuthenticationEvidence AuthenticationEvidence { get; }
}
