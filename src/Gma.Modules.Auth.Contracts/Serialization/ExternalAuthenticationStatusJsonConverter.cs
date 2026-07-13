namespace Gma.Modules.Auth.Contracts;

using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class ExternalAuthenticationStatusJsonConverter : JsonConverter<ExternalAuthenticationStatus>
{
    public override ExternalAuthenticationStatus Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.String)
        {
            throw new JsonException("External authentication status must be a string.");
        }

        return ExternalAuthenticationStatusNames.TryParse(reader.GetString(), out ExternalAuthenticationStatus status)
            ? status
            : throw new JsonException("External authentication status is invalid.");
    }

    public override void Write(
        Utf8JsonWriter writer,
        ExternalAuthenticationStatus value,
        JsonSerializerOptions options)
    {
        try
        {
            writer.WriteStringValue(ExternalAuthenticationStatusNames.ToWireName(value));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new JsonException("External authentication status is invalid.", exception);
        }
    }
}
