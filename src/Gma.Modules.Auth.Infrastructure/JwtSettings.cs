namespace Gma.Modules.Auth.Infrastructure;

public sealed class JwtSettings
{
    public const string SectionName = "Auth:Jwt";
    public const int MinimumSigningKeyBytes = 32;

    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public string SigningKey { get; set; } = string.Empty;
    public string ActiveSigningKeyId { get; set; } = "primary";
    public Dictionary<string, string> SigningKeys { get; set; } = new(StringComparer.Ordinal);
    public int AccessTokenLifetimeMinutes { get; set; } = 15;

    internal IReadOnlyDictionary<string, string> EffectiveSigningKeys => this.SigningKeys.Count > 0
        ? this.SigningKeys
        : new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [this.ActiveSigningKeyId] = this.SigningKey
        };
}
