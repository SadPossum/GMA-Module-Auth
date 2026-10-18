namespace Gma.Modules.Auth.Contracts;

using System.Text.Json.Serialization;

[JsonConverter(typeof(RememberedBrowserOutcomeJsonConverter))]
public enum RememberedBrowserOutcome
{
    Unknown = 0,
    Applied = 1,
    StateChanged = 2,
    AuthenticationRequired = 3,
    PinRejected = 4,
    RateLimited = 5,
    SessionLimitReached = 6,
    Unavailable = 7,
    NotFound = 8
}
