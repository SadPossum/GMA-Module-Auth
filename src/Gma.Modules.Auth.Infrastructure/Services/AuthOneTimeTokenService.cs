namespace Gma.Modules.Auth.Infrastructure.Services;

using System.Security.Cryptography;
using Gma.Modules.Auth.Domain.Services;

internal sealed class AuthOneTimeTokenService(IRefreshTokenHashingService hashingService)
    : IAuthOneTimeTokenService
{
    private const string HashDomain = "auth-one-time-token.v1";

    public string GenerateToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    public string HashToken(AuthOneTimeTokenPurpose purpose, string token) =>
        hashingService.HashRefreshToken(CreateHashInput(purpose, token));

    public IReadOnlyList<string> GetCandidateHashes(AuthOneTimeTokenPurpose purpose, string token) =>
        [.. hashingService.GetCandidateHashes(CreateHashInput(purpose, token))
            .Concat(hashingService.GetCandidateHashes(token.Trim()))
            .Distinct(StringComparer.Ordinal)];

    private static string CreateHashInput(AuthOneTimeTokenPurpose purpose, string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        string purposeName = purpose switch
        {
            AuthOneTimeTokenPurpose.ExternalAuthenticationExchange => "external-authentication-exchange",
            AuthOneTimeTokenPurpose.EmailVerification => "email-verification",
            AuthOneTimeTokenPurpose.PasswordRecovery => "password-recovery",
            AuthOneTimeTokenPurpose.MultiFactorChallenge => "multi-factor-challenge",
            AuthOneTimeTokenPurpose.MultiFactorRecoveryCode => "multi-factor-recovery-code",
            _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown Auth token purpose."),
        };
        return $"{HashDomain}\n{purposeName}\n{token.Trim()}";
    }
}
