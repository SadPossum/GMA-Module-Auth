namespace Gma.Modules.Auth.Providers.OpenIdConnect;

public sealed class AuthOpenIdConnectProviderOptions
{
    public bool Enabled { get; set; }
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string[] Scopes { get; set; } = ["openid", "email", "profile"];
    public string EmailClaim { get; set; } = "email";
    public string EmailVerifiedClaim { get; set; } = "email_verified";
    public bool TreatEmailAsVerified { get; set; }
}
