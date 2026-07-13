namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using Microsoft.Extensions.Options;

internal sealed class AuthOpenIdConnectOptionsValidator : IValidateOptions<AuthOpenIdConnectOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthOpenIdConnectOptions options)
    {
        if (options is null)
        {
            return ValidateOptionsResult.Fail($"{AuthOpenIdConnectOptions.SectionName} configuration is required.");
        }

        if (!options.Enabled)
        {
            return ValidateOptionsResult.Success;
        }

        if (options.Providers is null)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthOpenIdConnectOptions.SectionName}:Providers configuration is required.");
        }

        AuthOpenIdConnectProviderOptions[] enabledProviders = options.Providers.Values
            .Where(provider => provider?.Enabled == true)
            .ToArray();
        if (enabledProviders.Length == 0)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthOpenIdConnectOptions.SectionName} requires at least one enabled provider.");
        }

        HashSet<string> normalizedProviderKeys = new(StringComparer.Ordinal);
        foreach ((string key, AuthOpenIdConnectProviderOptions? provider) in options.Providers)
        {
            if (provider is null)
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key} configuration is required.");
            }

            if (!provider.Enabled)
            {
                continue;
            }

            if (!OpenIdConnectProviderRegistry.IsValidProviderKey(key))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers contains invalid key '{key}'.");
            }

            string normalizedProviderKey = OpenIdConnectProviderRegistry.NormalizeProviderKey(key);
            if (!normalizedProviderKeys.Add(normalizedProviderKey))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers contains duplicate normalized key '{normalizedProviderKey}'.");
            }

            if (!Uri.TryCreate(provider.Authority, UriKind.Absolute, out Uri? authority) ||
                authority.Scheme != Uri.UriSchemeHttps)
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key}:Authority must be an absolute HTTPS URL.");
            }

            if (string.IsNullOrWhiteSpace(provider.ClientId) || string.IsNullOrWhiteSpace(provider.ClientSecret))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key} requires ClientId and ClientSecret.");
            }

            if (!IsValidClaimName(provider.EmailClaim) || !IsValidClaimName(provider.EmailVerifiedClaim))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key} claim names must be non-empty, control-character-free, and at most 256 characters.");
            }

            if (provider.Scopes is null)
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key}:Scopes configuration is required.");
            }

            string[] scopes = provider.Scopes
                .Where(scope => !string.IsNullOrWhiteSpace(scope))
                .Select(scope => scope.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (!scopes.Contains("openid", StringComparer.Ordinal) ||
                !scopes.Contains("email", StringComparer.Ordinal))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key}:Scopes must include openid and email.");
            }
        }

        foreach (string returnUrl in options.AllowedReturnUrls ?? [])
        {
            if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:AllowedReturnUrls must contain absolute HTTPS URLs.");
            }
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsValidClaimName(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 256 &&
        !value.Any(char.IsControl);
}
