namespace Gma.Modules.Auth.Contracts;

using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class RememberedBrowserStateJsonConverter : JsonConverter<RememberedBrowserState>
{
    public override RememberedBrowserState Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.String)
        {
            throw new JsonException("Remembered-browser state must be a string.");
        }

        return RememberedBrowserStateNames.TryParse(reader.GetString(), out RememberedBrowserState state)
            ? state
            : throw new JsonException("Remembered-browser state is invalid.");
    }

    public override void Write(Utf8JsonWriter writer, RememberedBrowserState value, JsonSerializerOptions options)
    {
        try
        {
            writer.WriteStringValue(RememberedBrowserStateNames.ToWireName(value));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new JsonException("Remembered-browser state is invalid.", exception);
        }
    }
}
