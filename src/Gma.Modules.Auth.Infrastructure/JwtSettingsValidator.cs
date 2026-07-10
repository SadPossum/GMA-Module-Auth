namespace Gma.Modules.Auth.Infrastructure;

using System.Text;
using Microsoft.Extensions.Options;

internal sealed class JwtSettingsValidator : IValidateOptions<JwtSettings>
{
    public ValidateOptionsResult Validate(string? name, JwtSettings options)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            return ValidateOptionsResult.Fail($"{JwtSettings.SectionName}:Issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            return ValidateOptionsResult.Fail($"{JwtSettings.SectionName}:Audience is required.");
        }

        if (string.IsNullOrWhiteSpace(options.ActiveSigningKeyId))
        {
            return ValidateOptionsResult.Fail($"{JwtSettings.SectionName}:ActiveSigningKeyId is required.");
        }

        IReadOnlyDictionary<string, string> signingKeys = options.EffectiveSigningKeys;
        if (!signingKeys.TryGetValue(options.ActiveSigningKeyId, out string? activeSigningKey))
        {
            return ValidateOptionsResult.Fail(
                $"{JwtSettings.SectionName}:SigningKeys must contain ActiveSigningKeyId '{options.ActiveSigningKeyId}'.");
        }

        if (signingKeys.Any(pair =>
                string.IsNullOrWhiteSpace(pair.Key) ||
                string.IsNullOrWhiteSpace(pair.Value) ||
                Encoding.UTF8.GetByteCount(pair.Value) < JwtSettings.MinimumSigningKeyBytes))
        {
            return ValidateOptionsResult.Fail(
                $"{JwtSettings.SectionName}:SigningKeys entries must have non-empty ids and keys of at least " +
                $"{JwtSettings.MinimumSigningKeyBytes} bytes.");
        }

        if (options.AccessTokenLifetimeMinutes <= 0)
        {
            return ValidateOptionsResult.Fail($"{JwtSettings.SectionName}:AccessTokenLifetimeMinutes must be positive.");
        }

        return ValidateOptionsResult.Success;
    }
}
