namespace Gma.Modules.Auth.Providers.OpenIdConnect;

public sealed class AuthOpenIdConnectOptions
{
    public const string SectionName = "Auth:OpenIdConnect";

    public bool Enabled { get; set; }
    public string[] AllowedReturnUrls { get; set; } = [];
    public Dictionary<string, AuthOpenIdConnectProviderOptions> Providers { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);
}
