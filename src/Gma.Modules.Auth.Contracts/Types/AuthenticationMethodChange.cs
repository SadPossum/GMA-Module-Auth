namespace Gma.Modules.Auth.Contracts;

using System.Text.Json.Serialization;

[JsonConverter(typeof(AuthenticationMethodChangeJsonConverter))]
public enum AuthenticationMethodChange
{
    Unknown = 0,
    Added = 1,
    Updated = 2,
    Removed = 3,
}
