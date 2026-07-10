namespace Gma.Modules.Auth.Infrastructure;

public sealed class RefreshTokenHashingOptions
{
    public const string SectionName = "Auth:RefreshTokens";
    public const int MinimumPepperBytes = 32;

    public string Pepper { get; set; } = string.Empty;
    public string ActivePepperId { get; set; } = "primary";
    public Dictionary<string, string> Peppers { get; set; } = new(StringComparer.Ordinal);

    internal IReadOnlyDictionary<string, string> EffectivePeppers => this.Peppers.Count > 0
        ? this.Peppers
        : new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [this.ActivePepperId] = this.Pepper
        };
}
