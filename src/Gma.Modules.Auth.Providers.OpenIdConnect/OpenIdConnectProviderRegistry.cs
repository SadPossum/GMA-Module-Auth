namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using System.Text.RegularExpressions;

internal sealed partial class OpenIdConnectProviderRegistry(AuthOpenIdConnectOptions options)
{
    private const string SchemePrefix = "gma.auth.external.";
    private readonly Dictionary<string, string> schemes = options.Enabled
        ? options.Providers
            .Where(pair => pair.Value.Enabled)
            .ToDictionary(
                pair => NormalizeProviderKey(pair.Key),
                pair => SchemePrefix + NormalizeProviderKey(pair.Key),
                StringComparer.Ordinal)
        : new Dictionary<string, string>(StringComparer.Ordinal);

    public bool TryGetScheme(string provider, out string scheme) =>
        this.schemes.TryGetValue(NormalizeProviderKey(provider), out scheme!);

    public static bool IsValidProviderKey(string provider) =>
        !string.IsNullOrWhiteSpace(provider) && ProviderKeyRegex().IsMatch(provider.Trim());

    public static string NormalizeProviderKey(string provider) => provider.Trim().ToLowerInvariant();

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex ProviderKeyRegex();
}
