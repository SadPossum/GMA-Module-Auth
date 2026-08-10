namespace Gma.Modules.Auth.Infrastructure.JwtBearer;

using Microsoft.Extensions.Options;

internal sealed class AuthBearerAdmissionOptionsValidator : IValidateOptions<AuthBearerAdmissionOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthBearerAdmissionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return Enum.IsDefined(options.Mode)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{AuthBearerAdmissionOptions.SectionName}:Mode is invalid.");
    }
}
