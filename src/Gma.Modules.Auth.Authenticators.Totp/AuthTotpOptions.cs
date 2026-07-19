namespace Gma.Modules.Auth.Authenticators.Totp;

public sealed class AuthTotpOptions
{
    public const string SectionName = "Auth:Totp";
    public const int IssuerMaxLength = 64;

    public string Issuer { get; set; } = "GMA";
}
