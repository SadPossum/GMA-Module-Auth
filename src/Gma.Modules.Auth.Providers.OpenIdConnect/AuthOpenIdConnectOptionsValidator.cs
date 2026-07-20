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

            if (!IsValidAuthority(provider.Authority))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key}:Authority must be a bounded absolute HTTPS URL without credentials, a query, or a fragment.");
            }

            if (!IsValidCredential(provider.ClientId, AuthOpenIdConnectProviderOptions.ClientIdMaxLength) ||
                !IsValidCredential(provider.ClientSecret, AuthOpenIdConnectProviderOptions.ClientSecretMaxLength))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key} requires bounded, control-character-free ClientId and ClientSecret values.");
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

            if (provider.Scopes.Length > AuthOpenIdConnectProviderOptions.ScopeLimit ||
                provider.Scopes.Any(scope => !IsValidScope(scope)))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key}:Scopes must contain at most " +
                    $"{AuthOpenIdConnectProviderOptions.ScopeLimit} valid OAuth scope tokens of " +
                    $"{AuthOpenIdConnectProviderOptions.ScopeMaxLength} characters or fewer.");
            }

            string[] scopes = provider.Scopes
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (!scopes.Contains("openid", StringComparer.Ordinal) ||
                !scopes.Contains("email", StringComparer.Ordinal))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:Providers:{key}:Scopes must include openid and email.");
            }
        }

        if (options.AllowedReturnUrls is null || options.AllowedReturnUrls.Length == 0)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthOpenIdConnectOptions.SectionName}:AllowedReturnUrls requires at least one explicit callback path.");
        }

        foreach (string returnUrl in options.AllowedReturnUrls)
        {
            if (!ExternalReturnUrlPolicy.TryNormalizeAllowedDestination(returnUrl, out _))
            {
                return ValidateOptionsResult.Fail(
                    $"{AuthOpenIdConnectOptions.SectionName}:AllowedReturnUrls must contain rooted local paths or " +
                    "absolute HTTPS callback URLs without query strings or fragments.");
            }
        }

        return ValidateOptionsResult.Success;
    }

    private static bool IsValidClaimName(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 256 &&
        !value.Any(char.IsControl);

    private static bool IsValidAuthority(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > AuthOpenIdConnectProviderOptions.AuthorityMaxLength ||
            value.Any(char.IsControl) ||
            !Uri.TryCreate(value, UriKind.Absolute, out Uri? authority))
        {
            return false;
        }

        return authority.Scheme == Uri.UriSchemeHttps &&
               !string.IsNullOrWhiteSpace(authority.Host) &&
               string.IsNullOrEmpty(authority.UserInfo) &&
               string.IsNullOrEmpty(authority.Query) &&
               string.IsNullOrEmpty(authority.Fragment);
    }

    private static bool IsValidCredential(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        !value.Any(char.IsControl);

    private static bool IsValidScope(string? value) =>
        !string.IsNullOrEmpty(value) &&
        value.Length <= AuthOpenIdConnectProviderOptions.ScopeMaxLength &&
        value.All(character =>
            character is '\u0021' or
                (>= '\u0023' and <= '\u005B') or
                (>= '\u005D' and <= '\u007E'));
}
