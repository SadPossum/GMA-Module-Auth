namespace Gma.Modules.Auth.Application;

using Microsoft.Extensions.Options;

internal sealed class AuthApplicationOptionsValidator : IValidateOptions<AuthApplicationOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthApplicationOptions options)
    {
        if (options.RefreshTokenLifetimeDays <= 0)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:RefreshTokenLifetimeDays must be positive.");
        }

        if (options.FailedLoginLimit is < 1 or > 100)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:FailedLoginLimit must be between 1 and 100.");
        }

        if (options.FailedLoginWindowMinutes is < 1 or > 1_440)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:FailedLoginWindowMinutes must be between 1 and 1440.");
        }

        return ValidateOptionsResult.Success;
    }
}
