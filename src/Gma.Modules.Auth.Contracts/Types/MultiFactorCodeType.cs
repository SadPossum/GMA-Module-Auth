namespace Gma.Modules.Auth.Contracts;

using System.Text.Json.Serialization;

[JsonConverter(typeof(MultiFactorCodeTypeJsonConverter))]
public enum MultiFactorCodeType
{
    Unknown = 0,
    Totp = 1,
    RecoveryCode = 2,
}
