namespace Gma.Modules.Auth.Application.Ports;

public interface ITimeBasedOneTimePasswordProvider
{
    bool IsAvailable { get; }
    GeneratedTotpSecret GenerateSecret();
    string CreateProvisioningUri(string accountName, string encodedSecret);
    TotpVerificationResult Verify(byte[] secret, string code, DateTimeOffset nowUtc);
}

public sealed record GeneratedTotpSecret(byte[] Bytes, string Encoded);

public readonly record struct TotpVerificationResult(bool IsValid, long MatchedTimeStep)
{
    public static TotpVerificationResult Invalid => new(false, -1);
}
