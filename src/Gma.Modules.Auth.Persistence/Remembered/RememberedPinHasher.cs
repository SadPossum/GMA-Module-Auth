namespace Gma.Modules.Auth.Persistence.Remembered;

using System.Security.Cryptography;
using System.Text;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.Extensions.Options;

internal sealed class RememberedPinHasher(
    IOptions<RememberedBrowserOptions> options,
    IPasswordHashingService passwords,
    RememberedPinKdfCapacity capacity)
{

    public static bool IsValid(string? pin, int digits) =>
        pin is not null && pin.Length == digits && pin.All(char.IsAsciiDigit);

    public async Task<string> HashAsync(Guid deviceId, Guid proofId, string pin, CancellationToken cancellationToken)
    {
        await capacity.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return passwords.HashPassword(this.Prepare(deviceId, proofId, pin));
        }
        finally
        {
            capacity.Gate.Release();
        }
    }

    public async Task<bool> VerifyAsync(RememberedAccountProof proof, string pin, CancellationToken cancellationToken)
    {
        if (!string.Equals(proof.PepperVersion, options.Value.PepperVersion, StringComparison.Ordinal))
        {
            return false;
        }

        await capacity.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return passwords.VerifyPassword(proof.PinHash, this.Prepare(proof.DeviceId, proof.Id, pin))
                != PasswordVerificationOutcome.Unknown;
        }
        finally
        {
            capacity.Gate.Release();
        }
    }

    private string Prepare(Guid deviceId, Guid proofId, string pin)
    {
        byte[] key = Convert.FromBase64String(options.Value.Pepper);
        try
        {
            return Convert.ToBase64String(HMACSHA256.HashData(
                key,
                Encoding.UTF8.GetBytes($"gma.remembered.pin.v1|{deviceId:N}|{proofId:N}|{pin}")));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}

internal sealed class RememberedPinKdfCapacity(IOptions<RememberedBrowserOptions> options) : IDisposable
{
    public SemaphoreSlim Gate { get; } = new(options.Value.MaximumConcurrentKdf);
    public void Dispose() => this.Gate.Dispose();
}
