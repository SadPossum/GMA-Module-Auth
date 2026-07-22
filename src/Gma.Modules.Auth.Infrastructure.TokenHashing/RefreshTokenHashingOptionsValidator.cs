namespace Gma.Modules.Auth.Infrastructure.TokenHashing;

using System.Text;
using Microsoft.Extensions.Options;

internal sealed class RefreshTokenHashingOptionsValidator : IValidateOptions<RefreshTokenHashingOptions>
{
    public ValidateOptionsResult Validate(string? name, RefreshTokenHashingOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ActivePepperId))
        {
            return ValidateOptionsResult.Fail(
                $"{RefreshTokenHashingOptions.SectionName}:ActivePepperId is required.");
        }

        IReadOnlyDictionary<string, string> peppers = options.EffectivePeppers;
        if (!peppers.ContainsKey(options.ActivePepperId))
        {
            return ValidateOptionsResult.Fail(
                $"{RefreshTokenHashingOptions.SectionName}:Peppers must contain ActivePepperId '{options.ActivePepperId}'.");
        }

        if (peppers.Any(pair =>
                string.IsNullOrWhiteSpace(pair.Key) ||
                string.IsNullOrWhiteSpace(pair.Value) ||
                Encoding.UTF8.GetByteCount(pair.Value) < RefreshTokenHashingOptions.MinimumPepperBytes))
        {
            return ValidateOptionsResult.Fail(
                $"{RefreshTokenHashingOptions.SectionName}:Peppers entries must have non-empty ids and values of at least " +
                $"{RefreshTokenHashingOptions.MinimumPepperBytes} bytes.");
        }

        return ValidateOptionsResult.Success;
    }
}
