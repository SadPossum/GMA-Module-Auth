namespace Gma.Modules.Auth.Contracts;

public static class ExternalAuthenticationStatusNames
{
    public static string ToWireName(ExternalAuthenticationStatus status) =>
        status switch
        {
            ExternalAuthenticationStatus.Authenticated => "authenticated",
            ExternalAuthenticationStatus.Linked => "linked",
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, "External authentication status is invalid."),
        };

    public static bool TryParse(string? value, out ExternalAuthenticationStatus status)
    {
        status = (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "authenticated" => ExternalAuthenticationStatus.Authenticated,
            "linked" => ExternalAuthenticationStatus.Linked,
            _ => ExternalAuthenticationStatus.Unknown,
        };
        return status is not ExternalAuthenticationStatus.Unknown;
    }
}
