namespace Gma.Modules.Auth.Domain.Entities;

public static class MemberAuthenticationMethods
{
    public const string Password = "password";
    public const string Totp = "totp";
    public const string ExternalPrefix = "external:";
    public const int MaxLength = 256;

    public static string External(string provider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        return ExternalPrefix + MemberExternalIdentity.NormalizeProvider(provider);
    }

    public static bool TryNormalize(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string candidate = value.Trim().ToLowerInvariant();
        if (candidate.Length > MaxLength ||
            (candidate != Password &&
             candidate != Totp &&
             !candidate.StartsWith(ExternalPrefix, StringComparison.Ordinal)))
        {
            return false;
        }

        if (candidate.StartsWith(ExternalPrefix, StringComparison.Ordinal) &&
            candidate.Length == ExternalPrefix.Length)
        {
            return false;
        }

        normalized = candidate;
        return true;
    }
}
