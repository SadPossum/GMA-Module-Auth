namespace Gma.Modules.Auth.Infrastructure.Services;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Gma.Framework.Security;
using Gma.Framework.Runtime.Time;

internal sealed class JwtTokenService(IOptions<JwtSettings> options, ISystemClock clock) : ITokenService
{
    public string GenerateAccessToken(AccessTokenClaims accessTokenClaims)
    {
        ArgumentNullException.ThrowIfNull(accessTokenClaims);
        JwtSettings settings = options.Value;
        string activeSigningKey = settings.EffectiveSigningKeys[settings.ActiveSigningKeyId];
        SymmetricSecurityKey securityKey = new(Encoding.UTF8.GetBytes(activeSigningKey))
        {
            KeyId = settings.ActiveSigningKeyId
        };
        SigningCredentials signingCredentials = new(securityKey, SecurityAlgorithms.HmacSha256);

        List<Claim> claims =
        [
            new Claim(ApplicationClaimNames.Subject, accessTokenClaims.MemberId.Value.ToString()),
            new Claim(ApplicationClaimNames.ScopeId, accessTokenClaims.ScopeId),
            new Claim(ApplicationClaimNames.SessionId, accessTokenClaims.SessionId.Value.ToString()),
            new Claim(
                ApplicationClaimNames.AuthenticationContextReference,
                accessTokenClaims.AuthenticationEvidence.ContextReference),
            new Claim(
                ApplicationClaimNames.AuthenticationTime,
                accessTokenClaims.AuthenticationEvidence.AuthenticatedAtUtc.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64)
        ];
        claims.AddRange(accessTokenClaims.AuthenticationEvidence.MethodReferences.Select(methodReference =>
            new Claim(ApplicationClaimNames.AuthenticationMethodReference, methodReference)));

        DateTimeOffset nowUtc = clock.UtcNow;
        JwtSecurityToken token = new(
            issuer: settings.Issuer,
            audience: settings.Audience,
            claims: claims,
            notBefore: nowUtc.UtcDateTime,
            expires: nowUtc.AddMinutes(settings.AccessTokenLifetimeMinutes).UtcDateTime,
            signingCredentials: signingCredentials);

        return CreateTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    public MemberId? GetMemberId(string accessToken, bool validateLifetime)
    {
        AccessTokenClaims? claims = this.GetAccessTokenClaims(accessToken, validateLifetime);

        return claims?.MemberId;
    }

    public AccessTokenClaims? GetAccessTokenClaims(string accessToken, bool validateLifetime)
    {
        TokenValidationParameters parameters = this.CreateValidationParameters(validateLifetime);
        JwtSecurityTokenHandler handler = CreateTokenHandler();

        try
        {
            ClaimsPrincipal principal = handler.ValidateToken(accessToken, parameters, out _);
            string? memberIdValue = principal.FindFirstValue(ApplicationClaimNames.Subject) ??
                principal.FindFirstValue(ClaimTypes.NameIdentifier);
            string? scopeId = principal.FindFirstValue(ApplicationClaimNames.ScopeId);
            string? sessionIdValue = principal.FindFirstValue(ApplicationClaimNames.SessionId);
            string? contextReference = principal.FindFirstValue(ApplicationClaimNames.AuthenticationContextReference);
            string? authenticationTimeValue = principal.FindFirstValue(ApplicationClaimNames.AuthenticationTime);
            string[] methodReferences =
            [
                .. principal.FindAll(ApplicationClaimNames.AuthenticationMethodReference)
                    .Select(claim => claim.Value)
            ];

            if (!Guid.TryParse(memberIdValue, out Guid memberId) ||
                !Guid.TryParse(sessionIdValue, out Guid sessionId))
            {
                return null;
            }

            SessionAuthenticationEvidence evidence =
                !string.IsNullOrWhiteSpace(contextReference) &&
                long.TryParse(
                    authenticationTimeValue,
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out long authenticationTimeSeconds)
                    ? new SessionAuthenticationEvidence(
                        contextReference,
                        methodReferences,
                        DateTimeOffset.FromUnixTimeSeconds(authenticationTimeSeconds))
                    : SessionAuthenticationEvidence.Legacy(DateTimeOffset.UnixEpoch);

            return new AccessTokenClaims(
                new MemberId(memberId),
                scopeId!,
                new MemberSessionId(sessionId),
                evidence);
        }
        catch (SecurityTokenException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    internal TokenValidationParameters CreateValidationParameters(bool validateLifetime)
    {
        return JwtTokenValidationParametersFactory.Create(options.Value, validateLifetime);
    }

    private static JwtSecurityTokenHandler CreateTokenHandler() => new()
    {
        MapInboundClaims = false
    };
}
