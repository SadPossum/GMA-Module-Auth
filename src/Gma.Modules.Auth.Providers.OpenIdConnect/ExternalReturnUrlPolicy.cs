namespace Gma.Modules.Auth.Providers.OpenIdConnect;

internal sealed class ExternalReturnUrlPolicy(AuthOpenIdConnectOptions options)
{
    private static readonly Uri LocalBaseUri = new("https://gma.invalid", UriKind.Absolute);
    private readonly HashSet<string> allowedDestinations = (options.AllowedReturnUrls ?? [])
        .Select(returnUrl => TryNormalizeAllowedDestination(returnUrl, out string normalized)
            ? normalized
            : throw new ArgumentException("Configured OpenID Connect return URL is invalid.", nameof(options)))
        .ToHashSet(StringComparer.Ordinal);

    public bool TryValidate(string? returnUrl, out string validatedReturnUrl)
    {
        validatedReturnUrl = string.Empty;
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return false;
        }

        string candidate = returnUrl.Trim();
        if (!TryNormalizeCandidate(candidate, out string normalized) ||
            !this.allowedDestinations.Contains(normalized))
        {
            return false;
        }

        validatedReturnUrl = candidate;
        return true;
    }

    internal static bool TryNormalizeAllowedDestination(string? returnUrl, out string normalized)
    {
        normalized = string.Empty;
        if (!TryNormalizeCandidate(returnUrl, out normalized))
        {
            return false;
        }

        string candidate = returnUrl!.Trim();
        if (candidate.StartsWith('/'))
        {
            return !candidate.Contains('?') && !candidate.Contains('#');
        }

        return Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) &&
            string.IsNullOrEmpty(uri.Query) &&
            string.IsNullOrEmpty(uri.Fragment);
    }

    private static bool TryNormalizeCandidate(string? returnUrl, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(returnUrl) ||
            returnUrl.Length > 2_048 ||
            returnUrl.Any(char.IsControl))
        {
            return false;
        }

        string candidate = returnUrl.Trim();
        if (candidate.StartsWith('/'))
        {
            if (candidate.StartsWith("//", StringComparison.Ordinal) ||
                candidate.StartsWith("/\\", StringComparison.Ordinal) ||
                candidate.Contains('\\') ||
                candidate.Contains('#') ||
                !Uri.TryCreate(LocalBaseUri, candidate, out Uri? localUri))
            {
                return false;
            }

            normalized = $"local:{localUri.AbsolutePath}";
            return true;
        }

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        normalized = $"absolute:{uri.GetLeftPart(UriPartial.Path)}";
        return true;
    }
}
