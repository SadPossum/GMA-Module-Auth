namespace Gma.Modules.Auth.Infrastructure.Services;

using System.Security.Cryptography;
using System.Text;
using Gma.Modules.Auth.Domain.Services;
using Microsoft.Extensions.Options;

internal sealed class RefreshTokenHashingService(IOptions<RefreshTokenHashingOptions> options)
    : IRefreshTokenHashingService
{
    private const string AlgorithmPrefix = "hmac-sha256";

    public string HashRefreshToken(string refreshToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

        RefreshTokenHashingOptions settings = options.Value;
        return Hash(refreshToken, settings.ActivePepperId, settings.EffectivePeppers[settings.ActivePepperId]);
    }

    public IReadOnlyList<string> GetCandidateHashes(string refreshToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

        return [.. options.Value.EffectivePeppers.SelectMany(pair => new[]
        {
            Hash(refreshToken, pair.Key, pair.Value),
            HashLegacy(refreshToken, pair.Value)
        }).Distinct(StringComparer.Ordinal)];
    }

    private static string Hash(string refreshToken, string pepperId, string pepper)
    {
        byte[] key = Encoding.UTF8.GetBytes(pepper);
        byte[] data = Encoding.UTF8.GetBytes(refreshToken);
        byte[] hash = HMACSHA256.HashData(key, data);

        return $"{AlgorithmPrefix}:{pepperId}:{Convert.ToBase64String(hash)}";
    }

    private static string HashLegacy(string refreshToken, string pepper)
    {
        byte[] key = Encoding.UTF8.GetBytes(pepper);
        byte[] data = Encoding.UTF8.GetBytes(refreshToken);
        byte[] hash = HMACSHA256.HashData(key, data);

        return $"{AlgorithmPrefix}:{Convert.ToBase64String(hash)}";
    }
}
