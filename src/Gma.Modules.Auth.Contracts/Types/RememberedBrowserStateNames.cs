namespace Gma.Modules.Auth.Contracts;

public static class RememberedBrowserStateNames
{
    public static string ToWireName(RememberedBrowserState state) =>
        state switch
        {
            RememberedBrowserState.Missing => "missing",
            RememberedBrowserState.Locked => "locked",
            RememberedBrowserState.Active => "active",
            RememberedBrowserState.SigningIn => "signing-in",
            RememberedBrowserState.Revoked => "revoked",
            RememberedBrowserState.Unavailable => "unavailable",
            _ => throw new ArgumentOutOfRangeException(nameof(state), state, "Remembered-browser state is invalid.")
        };

    public static bool TryParse(string? value, out RememberedBrowserState state)
    {
        state = (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "missing" => RememberedBrowserState.Missing,
            "locked" => RememberedBrowserState.Locked,
            "active" => RememberedBrowserState.Active,
            "signing-in" => RememberedBrowserState.SigningIn,
            "revoked" => RememberedBrowserState.Revoked,
            "unavailable" => RememberedBrowserState.Unavailable,
            _ => RememberedBrowserState.Unknown
        };
        return state is not RememberedBrowserState.Unknown;
    }
}
