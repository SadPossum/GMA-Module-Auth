namespace Gma.Modules.Auth.Providers.OpenIdConnect;

internal sealed class ExternalReturnUrlPolicy(AuthOpenIdConnectOptions options)
{
    private readonly string[] allowedOrigins = (options.AllowedReturnUrls ?? [])
        .Select(url => new Uri(url, UriKind.Absolute).GetLeftPart(UriPartial.Authority))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    public bool TryValidate(string? returnUrl, out string validatedReturnUrl)
    {
        validatedReturnUrl = string.Empty;
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return false;
        }

        string candidate = returnUrl.Trim();
        if (candidate.StartsWith('/') &&
            !candidate.StartsWith("//", StringComparison.Ordinal) &&
            !candidate.StartsWith("/\\", StringComparison.Ordinal))
        {
            validatedReturnUrl = candidate;
            return true;
        }

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        string origin = uri.GetLeftPart(UriPartial.Authority);
        if (!this.allowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        validatedReturnUrl = uri.AbsoluteUri;
        return true;
    }
}
