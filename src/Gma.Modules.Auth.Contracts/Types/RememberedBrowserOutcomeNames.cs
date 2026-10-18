namespace Gma.Modules.Auth.Contracts;

public static class RememberedBrowserOutcomeNames
{
    public static string ToWireName(RememberedBrowserOutcome outcome) =>
        outcome switch
        {
            RememberedBrowserOutcome.Applied => "applied",
            RememberedBrowserOutcome.StateChanged => "state-changed",
            RememberedBrowserOutcome.AuthenticationRequired => "authentication-required",
            RememberedBrowserOutcome.PinRejected => "pin-rejected",
            RememberedBrowserOutcome.RateLimited => "rate-limited",
            RememberedBrowserOutcome.SessionLimitReached => "session-limit-reached",
            RememberedBrowserOutcome.Unavailable => "unavailable",
            RememberedBrowserOutcome.NotFound => "not-found",
            _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Remembered-browser outcome is invalid.")
        };

    public static bool TryParse(string? value, out RememberedBrowserOutcome outcome)
    {
        outcome = (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "applied" => RememberedBrowserOutcome.Applied,
            "state-changed" => RememberedBrowserOutcome.StateChanged,
            "authentication-required" => RememberedBrowserOutcome.AuthenticationRequired,
            "pin-rejected" => RememberedBrowserOutcome.PinRejected,
            "rate-limited" => RememberedBrowserOutcome.RateLimited,
            "session-limit-reached" => RememberedBrowserOutcome.SessionLimitReached,
            "unavailable" => RememberedBrowserOutcome.Unavailable,
            "not-found" => RememberedBrowserOutcome.NotFound,
            _ => RememberedBrowserOutcome.Unknown
        };
        return outcome is not RememberedBrowserOutcome.Unknown;
    }
}
