namespace Gma.Modules.Auth.Application;

public sealed class AuthSelfRegistrationOptions
{
    public bool PasswordEnabled { get; set; } = true;
    public bool ExternalEnabled { get; set; } = true;
}
