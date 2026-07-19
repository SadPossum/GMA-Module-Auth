namespace Gma.Modules.Auth.Contracts;

using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class MultiFactorCodeTypeJsonConverter : JsonConverter<MultiFactorCodeType>
{
    public override MultiFactorCodeType Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.String)
        {
            throw new JsonException("Multi-factor code type must be a string.");
        }

        return MultiFactorCodeTypeNames.TryParse(reader.GetString(), out MultiFactorCodeType codeType)
            ? codeType
            : throw new JsonException("Multi-factor code type is invalid.");
    }

    public override void Write(
        Utf8JsonWriter writer,
        MultiFactorCodeType value,
        JsonSerializerOptions options)
    {
        try
        {
            writer.WriteStringValue(MultiFactorCodeTypeNames.ToWireName(value));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new JsonException("Multi-factor code type is invalid.", exception);
        }
    }
}
