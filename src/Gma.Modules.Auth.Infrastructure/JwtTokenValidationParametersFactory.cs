namespace Gma.Modules.Auth.Infrastructure;

using System.Text;
using Microsoft.IdentityModel.Tokens;

public static class JwtTokenValidationParametersFactory
{
    public static TokenValidationParameters Create(JwtSettings settings, bool validateLifetime)
    {
        ArgumentNullException.ThrowIfNull(settings);
        SecurityKey[] signingKeys = [.. settings.EffectiveSigningKeys.Select(pair =>
            (SecurityKey)new SymmetricSecurityKey(Encoding.UTF8.GetBytes(pair.Value))
            {
                KeyId = pair.Key
            })];

        return new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = validateLifetime,
            ValidIssuer = settings.Issuer,
            ValidAudience = settings.Audience,
            IssuerSigningKeys = signingKeys,
            TryAllIssuerSigningKeys = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.Zero
        };
    }
}
