namespace Gma.Modules.Auth.Authenticators.Totp;

using Gma.Modules.Auth.Application.Ports;
using Microsoft.AspNetCore.DataProtection;

internal sealed class DataProtectionAuthenticatorSecretProtector : IAuthenticatorSecretProtector
{
    private const string Purpose = "Gma.Modules.Auth.TotpAuthenticatorSecret.v1";
    private readonly IDataProtector protector;

    public DataProtectionAuthenticatorSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        this.protector = provider.CreateProtector(Purpose);
    }

    public bool IsAvailable => true;

    public string Protect(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return Convert.ToBase64String(this.protector.Protect(secret));
    }

    public byte[] Unprotect(string protectedSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedSecret);
        return this.protector.Unprotect(Convert.FromBase64String(protectedSecret.Trim()));
    }
}
