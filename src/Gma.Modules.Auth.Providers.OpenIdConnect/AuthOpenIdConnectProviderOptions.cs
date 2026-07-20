namespace Gma.Modules.Auth.Providers.OpenIdConnect;

public sealed class AuthOpenIdConnectProviderOptions
{
    public const int AuthorityMaxLength = 2_048;
    public const int ClientIdMaxLength = 2_048;
    public const int ClientSecretMaxLength = 4_096;
    public const int ScopeLimit = 64;
    public const int ScopeMaxLength = 256;

    public bool Enabled { get; set; }
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string[] Scopes { get; set; } = ["openid", "email", "profile"];
    public string EmailClaim { get; set; } = "email";
    public string EmailVerifiedClaim { get; set; } = "email_verified";
    public bool TreatEmailAsVerified { get; set; }
}
