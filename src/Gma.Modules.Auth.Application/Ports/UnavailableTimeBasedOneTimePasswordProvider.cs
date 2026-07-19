namespace Gma.Modules.Auth.Application.Ports;

internal sealed class UnavailableTimeBasedOneTimePasswordProvider : ITimeBasedOneTimePasswordProvider
{
    public bool IsAvailable => false;

    public GeneratedTotpSecret GenerateSecret() => throw CreateException();

    public string CreateProvisioningUri(string accountName, string encodedSecret) =>
        throw CreateException();

    public TotpVerificationResult Verify(byte[] secret, string code, DateTimeOffset nowUtc) =>
        throw CreateException();

    private static InvalidOperationException CreateException() =>
        new("No TOTP authenticator adapter is registered.");
}
