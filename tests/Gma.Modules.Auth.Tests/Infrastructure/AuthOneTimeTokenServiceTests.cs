namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Infrastructure.Services;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthOneTimeTokenServiceTests
{
    [Fact]
    public void Hashes_are_purpose_separated_and_legacy_candidates_remain_accepted()
    {
        var hashingService = new RecordingHashingService();
        var service = new AuthOneTimeTokenService(hashingService);

        string verificationHash = service.HashToken(AuthOneTimeTokenPurpose.EmailVerification, "same-token");
        string recoveryHash = service.HashToken(AuthOneTimeTokenPurpose.PasswordRecovery, "same-token");
        IReadOnlyList<string> candidates = service.GetCandidateHashes(
            AuthOneTimeTokenPurpose.EmailVerification,
            "same-token");

        Assert.NotEqual(verificationHash, recoveryHash);
        Assert.Contains(verificationHash, candidates);
        Assert.Contains("hash:same-token", candidates);
        Assert.Contains(hashingService.Inputs, input => input.Contains("email-verification", StringComparison.Ordinal));
        Assert.Contains(hashingService.Inputs, input => input.Contains("password-recovery", StringComparison.Ordinal));
    }

    private sealed class RecordingHashingService : IRefreshTokenHashingService
    {
        public List<string> Inputs { get; } = [];

        public string HashRefreshToken(string refreshToken)
        {
            this.Inputs.Add(refreshToken);
            return $"hash:{refreshToken}";
        }

        public IReadOnlyList<string> GetCandidateHashes(string refreshToken)
        {
            this.Inputs.Add(refreshToken);
            return [$"hash:{refreshToken}"];
        }
    }
}
