namespace Gma.Modules.Auth.Contracts;

using System.Text.Json.Serialization;

[JsonConverter(typeof(RememberedBrowserStateJsonConverter))]
public enum RememberedBrowserState
{
    Unknown = 0,
    Missing = 1,
    Locked = 2,
    Active = 3,
    SigningIn = 4,
    Revoked = 5,
    Unavailable = 6
}
