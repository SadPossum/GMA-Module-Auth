namespace Gma.Modules.Auth.Contracts;

using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class AuthenticationMethodChangeJsonConverter : JsonConverter<AuthenticationMethodChange>
{
    public override AuthenticationMethodChange Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.String)
        {
            throw new JsonException("Authentication method change must be a string.");
        }

        return AuthenticationMethodChangeNames.TryParse(reader.GetString(), out AuthenticationMethodChange change)
            ? change
            : throw new JsonException("Authentication method change is invalid.");
    }

    public override void Write(
        Utf8JsonWriter writer,
        AuthenticationMethodChange value,
        JsonSerializerOptions options)
    {
        try
        {
            writer.WriteStringValue(AuthenticationMethodChangeNames.ToWireName(value));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new JsonException("Authentication method change is invalid.", exception);
        }
    }
}
