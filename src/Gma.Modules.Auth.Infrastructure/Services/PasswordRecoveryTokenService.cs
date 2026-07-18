namespace Gma.Modules.Auth.Infrastructure.Services;

using Gma.Modules.Auth.Domain.Services;

internal sealed class PasswordRecoveryTokenService(
    ITokenService tokenService,
    IRefreshTokenHashingService hashingService)
    : IPasswordRecoveryTokenService
{
    public string GenerateCode() => tokenService.GenerateRefreshToken();

    public string HashCode(string code) => hashingService.HashRefreshToken(code);

    public IReadOnlyList<string> GetCandidateHashes(string code) => hashingService.GetCandidateHashes(code);
}
