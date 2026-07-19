namespace Gma.Modules.Auth.Infrastructure.Services;

using System.Security.Cryptography;
using Gma.Modules.Auth.Domain.Services;

internal sealed class MultiFactorTokenService(
    ITokenService tokenService,
    IRefreshTokenHashingService hashingService)
    : IMultiFactorTokenService
{
    private const int RecoveryCodeByteLength = 16;

    public MultiFactorTokenMaterial GenerateChallengeToken()
    {
        string plaintext = tokenService.GenerateRefreshToken();
        return new MultiFactorTokenMaterial(plaintext, hashingService.HashRefreshToken(plaintext));
    }

    public IReadOnlyList<string> GetCandidateChallengeTokenHashes(string token) =>
        hashingService.GetCandidateHashes(token.Trim());

    public IReadOnlyList<RecoveryCodeMaterial> GenerateRecoveryCodes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);

        List<RecoveryCodeMaterial> codes = new(count);
        for (int index = 0; index < count; index++)
        {
            string normalized = Convert.ToHexString(RandomNumberGenerator.GetBytes(RecoveryCodeByteLength));
            string plaintext = string.Join('-', Enumerable.Range(0, 4).Select(part => normalized.Substring(part * 8, 8)));
            codes.Add(new RecoveryCodeMaterial(plaintext, hashingService.HashRefreshToken(normalized)));
        }

        return codes;
    }

    public IReadOnlyList<string> GetCandidateRecoveryCodeHashes(string code) =>
        hashingService.GetCandidateHashes(NormalizeRecoveryCode(code));

    private static string NormalizeRecoveryCode(string code) =>
        new string(code.Where(character => character != '-' && !char.IsWhiteSpace(character)).ToArray())
            .ToUpperInvariant();
}
