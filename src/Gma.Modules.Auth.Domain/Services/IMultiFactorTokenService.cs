namespace Gma.Modules.Auth.Domain.Services;

public interface IMultiFactorTokenService
{
    MultiFactorTokenMaterial GenerateChallengeToken();
    IReadOnlyList<string> GetCandidateChallengeTokenHashes(string token);
    IReadOnlyList<RecoveryCodeMaterial> GenerateRecoveryCodes(int count);
    IReadOnlyList<string> GetCandidateRecoveryCodeHashes(string code);
}

public sealed record MultiFactorTokenMaterial(string Plaintext, string Hash);

public sealed record RecoveryCodeMaterial(string Plaintext, string Hash);
