namespace Gma.Modules.Auth.Contracts;

using System.Text.Json.Serialization;

[JsonConverter(typeof(ExternalAuthenticationStatusJsonConverter))]
public enum ExternalAuthenticationStatus
{
    Unknown = 0,
    Authenticated = 1,
    Linked = 2,
    MultiFactorRequired = 3,
}
