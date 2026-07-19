namespace Gma.Modules.Auth.Tests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Infrastructure;
using Gma.Modules.Auth.Infrastructure.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Gma.Framework.Security;
using Gma.Framework.Runtime.Time;
using Xunit;

[Trait("Category", "Unit")]
public sealed class JwtTokenServiceTests
{
    [Fact]
    public void Generate_access_token_normalizes_tenant_claim()
    {
        JwtTokenService service = CreateService();
        MemberId memberId = new(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        MemberSessionId sessionId = new(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"));

        DateTimeOffset authenticatedAtUtc = new(2026, 7, 2, 11, 55, 0, TimeSpan.Zero);
        string token = service.GenerateAccessToken(new AccessTokenClaims(
            memberId,
            " tenant-a ",
            sessionId,
            SessionAuthenticationEvidence.Password(authenticatedAtUtc)));
        AccessTokenClaims? claims = service.GetAccessTokenClaims(token, validateLifetime: false);

        Assert.NotNull(claims);
        Assert.Equal(memberId, claims.MemberId);
        Assert.Equal("tenant-a", claims.ScopeId);
        Assert.Equal(sessionId, claims.SessionId);
        Assert.Equal(AuthenticationContextReferences.Password, claims.AuthenticationEvidence.ContextReference);
        Assert.Equal([AuthenticationMethodReferences.Password], claims.AuthenticationEvidence.MethodReferences);
        Assert.Equal(authenticatedAtUtc, claims.AuthenticationEvidence.AuthenticatedAtUtc);
    }

    [Fact]
    public void Generate_access_token_rejects_invalid_identity()
    {
        JwtTokenService service = CreateService();
        MemberId memberId = new(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        MemberSessionId sessionId = new(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"));

        SessionAuthenticationEvidence evidence = SessionAuthenticationEvidence.Password(DateTimeOffset.UtcNow);
        Assert.Throws<ArgumentException>(() => service.GenerateAccessToken(
            new AccessTokenClaims(default, "tenant-a", sessionId, evidence)));
        Assert.Throws<ArgumentException>(() => service.GenerateAccessToken(
            new AccessTokenClaims(memberId, "tenant-a", default, evidence)));
        Assert.Throws<ArgumentException>(() => service.GenerateAccessToken(
            new AccessTokenClaims(memberId, " ", sessionId, evidence)));
    }

    [Fact]
    public void Get_access_token_claims_rejects_unexpected_signing_algorithm()
    {
        JwtSettings settings = CreateSettings();
        JwtTokenService service = CreateService(settings);
        MemberId memberId = new(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        MemberSessionId sessionId = new(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"));
        SymmetricSecurityKey securityKey = new(Encoding.UTF8.GetBytes(settings.SigningKey));
        SigningCredentials signingCredentials = new(securityKey, SecurityAlgorithms.HmacSha384);
        JwtSecurityToken token = new(
            issuer: settings.Issuer,
            audience: settings.Audience,
            claims:
            [
                new Claim(GmaClaimNames.Subject, memberId.Value.ToString()),
                new Claim(GmaClaimNames.ScopeId, "tenant-a"),
                new Claim(GmaClaimNames.SessionId, sessionId.Value.ToString())
            ],
            notBefore: new DateTime(2026, 7, 2, 12, 0, 0, DateTimeKind.Utc),
            expires: new DateTime(2026, 7, 2, 12, 15, 0, DateTimeKind.Utc),
            signingCredentials: signingCredentials);

        string accessToken = new JwtSecurityTokenHandler().WriteToken(token);

        Assert.Null(service.GetAccessTokenClaims(accessToken, validateLifetime: false));
    }

    [Fact]
    public void Legacy_access_token_can_be_identified_for_refresh_without_gaining_assurance()
    {
        JwtSettings settings = CreateSettings();
        JwtTokenService service = CreateService(settings);
        MemberId memberId = new(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        MemberSessionId sessionId = new(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"));
        SymmetricSecurityKey securityKey = new(Encoding.UTF8.GetBytes(settings.SigningKey));
        JwtSecurityToken token = new(
            issuer: settings.Issuer,
            audience: settings.Audience,
            claims:
            [
                new Claim(GmaClaimNames.Subject, memberId.Value.ToString()),
                new Claim(GmaClaimNames.ScopeId, "tenant-a"),
                new Claim(GmaClaimNames.SessionId, sessionId.Value.ToString())
            ],
            notBefore: new DateTime(2026, 7, 2, 12, 0, 0, DateTimeKind.Utc),
            expires: new DateTime(2026, 7, 2, 12, 15, 0, DateTimeKind.Utc),
            signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256));

        AccessTokenClaims? claims = service.GetAccessTokenClaims(
            new JwtSecurityTokenHandler().WriteToken(token),
            validateLifetime: false);

        Assert.NotNull(claims);
        Assert.Equal(AuthenticationContextReferences.Legacy, claims.AuthenticationEvidence.ContextReference);
        Assert.Empty(claims.AuthenticationEvidence.MethodReferences);
        Assert.Equal(DateTimeOffset.UnixEpoch, claims.AuthenticationEvidence.AuthenticatedAtUtc);
    }

    [Fact]
    public void Rotated_key_ring_accepts_previous_key_and_issues_with_active_key_id()
    {
        JwtSettings oldSettings = CreateSettings();
        JwtTokenService oldService = CreateService(oldSettings);
        MemberId memberId = new(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        MemberSessionId sessionId = new(Guid.Parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"));
        AccessTokenClaims claims = new(
            memberId,
            "tenant-a",
            sessionId,
            SessionAuthenticationEvidence.Password(new DateTimeOffset(2026, 7, 2, 11, 55, 0, TimeSpan.Zero)));
        string oldToken = oldService.GenerateAccessToken(claims);
        JwtSettings rotatedSettings = new()
        {
            Issuer = oldSettings.Issuer,
            Audience = oldSettings.Audience,
            ActiveSigningKeyId = "v2",
            SigningKeys = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["primary"] = oldSettings.SigningKey,
                ["v2"] = "rotated-signing-key-with-enough-bytes-000000000000000000"
            }
        };
        JwtTokenService rotatedService = CreateService(rotatedSettings);

        string newToken = rotatedService.GenerateAccessToken(claims);

        Assert.NotNull(rotatedService.GetAccessTokenClaims(oldToken, validateLifetime: false));
        Assert.Equal("v2", new JwtSecurityTokenHandler().ReadJwtToken(newToken).Header.Kid);
    }

    private static JwtTokenService CreateService(JwtSettings? settings = null) =>
        new(Options.Create(settings ?? CreateSettings()), new FixedClock(new DateTimeOffset(2026, 7, 2, 12, 0, 0, TimeSpan.Zero)));

    private static JwtSettings CreateSettings() =>
        new()
        {
            Issuer = "GMA.Tests",
            Audience = "GMA.Tests",
            SigningKey = "test-signing-key-with-enough-bytes-00000000000000000000",
            AccessTokenLifetimeMinutes = 15
        };

    private sealed class FixedClock(DateTimeOffset now) : ISystemClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
