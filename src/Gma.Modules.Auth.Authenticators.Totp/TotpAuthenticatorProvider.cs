namespace Gma.Modules.Auth.Authenticators.Totp;

using Gma.Modules.Auth.Application.Ports;
using Microsoft.Extensions.Options;
using OtpNet;

internal sealed class TotpAuthenticatorProvider(IOptions<AuthTotpOptions> options)
    : ITimeBasedOneTimePasswordProvider
{
    private const int SecretByteLength = 20;
    private const int CodeLength = 6;
    private static readonly VerificationWindow VerificationWindow = new(previous: 1, future: 0);

    public bool IsAvailable => true;

    public GeneratedTotpSecret GenerateSecret()
    {
        byte[] bytes = KeyGeneration.GenerateRandomKey(SecretByteLength);
        return new GeneratedTotpSecret(bytes, Base32Encoding.ToString(bytes));
    }

    public string CreateProvisioningUri(string accountName, string encodedSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        ArgumentException.ThrowIfNullOrWhiteSpace(encodedSecret);
        return new OtpUri(
            OtpType.Totp,
            encodedSecret.Trim(),
            accountName.Trim(),
            options.Value.Issuer.Trim()).ToString();
    }

    public TotpVerificationResult Verify(byte[] secret, string code, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0 || code.Length != CodeLength || code.Any(character => !char.IsAsciiDigit(character)))
        {
            return TotpVerificationResult.Invalid;
        }

        Totp totp = new(secret, step: 30, mode: OtpHashMode.Sha1, totpSize: CodeLength);
        bool valid = totp.VerifyTotp(
            nowUtc.UtcDateTime,
            code,
            out long matchedTimeStep,
            VerificationWindow);
        return valid ? new TotpVerificationResult(true, matchedTimeStep) : TotpVerificationResult.Invalid;
    }
}
