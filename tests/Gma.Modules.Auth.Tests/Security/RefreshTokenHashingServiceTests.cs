namespace Gma.Modules.Auth.Tests;

using System.Security.Cryptography;
using System.Text;
using Gma.Modules.Auth.Infrastructure.TokenHashing;
using Gma.Modules.Auth.Infrastructure.TokenHashing.Services;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class RefreshTokenHashingServiceTests
{
    private const string PepperA = "test-refresh-token-pepper-a-000000000000000000000000";
    private const string PepperB = "test-refresh-token-pepper-b-000000000000000000000000";

    [Fact]
    public void HashRefreshToken_returns_versioned_hmac_and_not_raw_sha256()
    {
        const string refreshToken = "refresh-token-value";
        var service = CreateService(PepperA);
        string rawSha256 = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));

        string hash = service.HashRefreshToken(refreshToken);
        string secondHash = service.HashRefreshToken(refreshToken);

        Assert.StartsWith("hmac-sha256:", hash, StringComparison.Ordinal);
        Assert.Equal(hash, secondHash);
        Assert.NotEqual(rawSha256, hash);
        Assert.DoesNotContain(refreshToken, hash, StringComparison.Ordinal);
    }

    [Fact]
    public void HashRefreshToken_changes_when_pepper_changes()
    {
        const string refreshToken = "refresh-token-value";

        string firstHash = CreateService(PepperA).HashRefreshToken(refreshToken);
        string secondHash = CreateService(PepperB).HashRefreshToken(refreshToken);

        Assert.NotEqual(firstHash, secondHash);
    }

    [Fact]
    public void Candidate_hashes_keep_previous_peppers_valid_during_rotation()
    {
        const string refreshToken = "refresh-token-value";
        RefreshTokenHashingService oldService = CreateService(PepperA);
        RefreshTokenHashingService rotatedService = new(Options.Create(new RefreshTokenHashingOptions
        {
            ActivePepperId = "v2",
            Peppers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["v2"] = PepperB,
                ["primary"] = PepperA
            }
        }));

        string oldHash = oldService.HashRefreshToken(refreshToken);
        IReadOnlyList<string> candidates = rotatedService.GetCandidateHashes(refreshToken);

        Assert.Contains(oldHash, candidates);
        Assert.StartsWith("hmac-sha256:v2:", rotatedService.HashRefreshToken(refreshToken), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("       ")]
    public void Options_validator_rejects_missing_or_short_pepper(string pepper)
    {
        var validator = new RefreshTokenHashingOptionsValidator();

        ValidateOptionsResult result = validator.Validate(
            name: null,
            new RefreshTokenHashingOptions { Pepper = pepper });

        Assert.True(result.Failed);
        Assert.Contains("Pepper", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Options_validator_rejects_default_settings_without_pepper()
    {
        var validator = new RefreshTokenHashingOptionsValidator();

        ValidateOptionsResult result = validator.Validate(name: null, new RefreshTokenHashingOptions());

        Assert.True(result.Failed);
        Assert.Contains("Pepper", result.FailureMessage, StringComparison.Ordinal);
    }

    private static RefreshTokenHashingService CreateService(string pepper) =>
        new(Options.Create(new RefreshTokenHashingOptions { Pepper = pepper }));
}
