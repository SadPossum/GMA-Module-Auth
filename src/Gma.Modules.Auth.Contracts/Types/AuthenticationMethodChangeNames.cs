namespace Gma.Modules.Auth.Contracts;

public static class AuthenticationMethodChangeNames
{
    public static string ToWireName(AuthenticationMethodChange change) =>
        change switch
        {
            AuthenticationMethodChange.Added => "added",
            AuthenticationMethodChange.Updated => "updated",
            AuthenticationMethodChange.Removed => "removed",
            _ => throw new ArgumentOutOfRangeException(nameof(change), change, "Authentication method change is invalid."),
        };

    public static bool TryParse(string? value, out AuthenticationMethodChange change)
    {
        change = (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "added" => AuthenticationMethodChange.Added,
            "updated" => AuthenticationMethodChange.Updated,
            "removed" => AuthenticationMethodChange.Removed,
            _ => AuthenticationMethodChange.Unknown,
        };
        return change is not AuthenticationMethodChange.Unknown;
    }
}
