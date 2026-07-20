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

    [Theory]
    [InlineData(0, 30)]
    [InlineData(3_651, 30)]
    [InlineData(29, 30)]
    public void Validate_rejects_invalid_absolute_session_lifetime(
        int sessionAbsoluteLifetimeDays,
        int refreshTokenLifetimeDays)
    {
        ValidateOptionsResult result = this.validator.Validate(
            name: null,
            new AuthApplicationOptions
            {
                RefreshTokenLifetimeDays = refreshTokenLifetimeDays,
                SessionAbsoluteLifetimeDays = sessionAbsoluteLifetimeDays,
            });

        Assert.True(result.Failed);
        Assert.Contains("SessionAbsoluteLifetimeDays", result.FailureMessage, StringComparison.Ordinal);
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

    [Theory]
    [InlineData(0, 60)]
    [InlineData(1_441, 60)]
    [InlineData(30, 0)]
    [InlineData(30, 3_601)]
    public void Validate_rejects_invalid_password_recovery_settings(int lifetimeMinutes, int cooldownSeconds)
    {
        ValidateOptionsResult result = this.validator.Validate(
            name: null,
            new AuthApplicationOptions
            {
                PasswordRecoveryLifetimeMinutes = lifetimeMinutes,
                PasswordRecoveryRequestCooldownSeconds = cooldownSeconds,
            });

        Assert.True(result.Failed);
        Assert.Contains("PasswordRecovery", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, 15)]
    [InlineData(21, 15)]
    [InlineData(5, 0)]
    [InlineData(5, 1_441)]
    public void Validate_rejects_invalid_multi_factor_management_limits(int attempts, int windowMinutes)
    {
        ValidateOptionsResult result = this.validator.Validate(
            name: null,
            new AuthApplicationOptions
            {
                MultiFactor = new AuthMultiFactorOptions
                {
                    ManagementMaximumAttempts = attempts,
                    ManagementAttemptWindowMinutes = windowMinutes,
                },
            });

        Assert.True(result.Failed);
        Assert.Contains("MultiFactor", result.FailureMessage, StringComparison.Ordinal);
    }
}
