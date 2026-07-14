namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthApplicationOptionsValidatorTests
{
    private readonly AuthApplicationOptionsValidator validator = new();

    [Fact]
    public void Validate_accepts_default_settings()
    {
        ValidateOptionsResult result = this.validator.Validate(name: null, new AuthApplicationOptions());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(3_651)]
    public void Validate_rejects_out_of_range_refresh_token_lifetime(int refreshTokenLifetimeDays)
    {
        ValidateOptionsResult result = this.validator.Validate(
            name: null,
            new AuthApplicationOptions { RefreshTokenLifetimeDays = refreshTokenLifetimeDays });

        Assert.True(result.Failed);
        Assert.Contains("RefreshTokenLifetimeDays", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_rejects_missing_self_registration_settings()
    {
        ValidateOptionsResult result = this.validator.Validate(
            name: null,
            new AuthApplicationOptions { SelfRegistration = null! });

        Assert.True(result.Failed);
        Assert.Contains("SelfRegistration", result.FailureMessage, StringComparison.Ordinal);
    }
}
