namespace Gma.Modules.Auth.Contracts;

using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class RememberedBrowserOutcomeJsonConverter : JsonConverter<RememberedBrowserOutcome>
{
    public override RememberedBrowserOutcome Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.String)
        {
            throw new JsonException("Remembered-browser outcome must be a string.");
        }

        return RememberedBrowserOutcomeNames.TryParse(reader.GetString(), out RememberedBrowserOutcome outcome)
            ? outcome
            : throw new JsonException("Remembered-browser outcome is invalid.");
    }

    public override void Write(Utf8JsonWriter writer, RememberedBrowserOutcome value, JsonSerializerOptions options)
    {
        try
        {
            writer.WriteStringValue(RememberedBrowserOutcomeNames.ToWireName(value));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new JsonException("Remembered-browser outcome is invalid.", exception);
        }
    }
}
