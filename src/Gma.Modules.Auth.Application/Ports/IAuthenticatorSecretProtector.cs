namespace Gma.Modules.Auth.Application.Ports;

public interface IAuthenticatorSecretProtector
{
    bool IsAvailable { get; }
    string Protect(byte[] secret);
    byte[] Unprotect(string protectedSecret);
}
