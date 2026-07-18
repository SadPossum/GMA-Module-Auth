namespace Gma.Modules.Auth.Domain.Services;

public interface IPasswordRecoveryTokenService
{
    string GenerateCode();
    string HashCode(string code);
    IReadOnlyList<string> GetCandidateHashes(string code);
}
