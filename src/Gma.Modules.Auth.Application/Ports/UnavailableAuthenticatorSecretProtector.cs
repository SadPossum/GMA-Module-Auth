namespace Gma.Modules.Auth.Application.Ports;

internal sealed class UnavailableAuthenticatorSecretProtector : IAuthenticatorSecretProtector
{
    public bool IsAvailable => false;

    public string Protect(byte[] secret) => throw CreateException();

    public byte[] Unprotect(string protectedSecret) => throw CreateException();

    private static InvalidOperationException CreateException() =>
        new("No authenticator secret protector is registered.");
}
