namespace Gma.Modules.Auth.Authenticators.Totp;

using Microsoft.Extensions.Options;

internal sealed class AuthTotpOptionsValidator : IValidateOptions<AuthTotpOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthTotpOptions options) =>
        string.IsNullOrWhiteSpace(options.Issuer) ||
        options.Issuer.Trim().Length > AuthTotpOptions.IssuerMaxLength ||
        options.Issuer.Any(char.IsControl)
            ? ValidateOptionsResult.Fail(
                $"{AuthTotpOptions.SectionName}:Issuer is required, must be {AuthTotpOptions.IssuerMaxLength} characters or fewer, and cannot contain control characters.")
            : ValidateOptionsResult.Success;
}
