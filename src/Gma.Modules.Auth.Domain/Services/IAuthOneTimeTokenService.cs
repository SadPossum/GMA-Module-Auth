namespace Gma.Modules.Auth.Domain.Services;

public interface IAuthOneTimeTokenService
{
    string GenerateToken();
    string HashToken(AuthOneTimeTokenPurpose purpose, string token);
    IReadOnlyList<string> GetCandidateHashes(AuthOneTimeTokenPurpose purpose, string token);
}

public enum AuthOneTimeTokenPurpose
{
    Unknown = 0,
    ExternalAuthenticationExchange = 1,
    EmailVerification = 2,
    PasswordRecovery = 3,
    MultiFactorChallenge = 4,
    MultiFactorRecoveryCode = 5,
}
