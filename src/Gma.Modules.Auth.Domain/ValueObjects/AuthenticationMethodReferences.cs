namespace Gma.Modules.Auth.Domain.ValueObjects;

public static class AuthenticationMethodReferences
{
    public const string Password = "pwd";
    public const string OneTimePassword = "otp";
    public const string MultiFactor = "mfa";
    public const string External = "urn:gma:amr:external";
    public const string RecoveryCode = "urn:gma:amr:recovery-code";
    public const string DevicePin = "urn:gma:amr:device-pin";
}
