namespace Gma.Modules.Auth.Contracts;

public sealed record AuthSelfRegistrationResponse(
    bool PasswordEnabled,
    bool ExternalEnabled);
