namespace Gma.Modules.Auth.Infrastructure.Services;

using Gma.Modules.Auth.Domain.Services;

internal sealed class PasswordRecoveryTokenService(
    IAuthOneTimeTokenService tokenService)
    : IPasswordRecoveryTokenService
{
    public string GenerateCode() => tokenService.GenerateToken();

    public string HashCode(string code) =>
        tokenService.HashToken(AuthOneTimeTokenPurpose.PasswordRecovery, code);

    public IReadOnlyList<string> GetCandidateHashes(string code) =>
        tokenService.GetCandidateHashes(AuthOneTimeTokenPurpose.PasswordRecovery, code);
}
