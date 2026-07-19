namespace Gma.Modules.Auth.Persistence.Configurations;

using System.Text.Json;

internal static class SessionAuthenticationMethodReferencesJson
{
    public const int MaxLength = 2048;

    public static string Serialize(string[] values) => JsonSerializer.Serialize(values);

    public static string[] Deserialize(string value) =>
        JsonSerializer.Deserialize<string[]>(value) ?? [];
}
