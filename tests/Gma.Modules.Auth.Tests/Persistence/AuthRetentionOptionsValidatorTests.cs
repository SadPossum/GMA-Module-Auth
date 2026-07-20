namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Persistence;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthRetentionOptionsValidatorTests
{
    private readonly AuthRetentionOptionsValidator validator = new();

    [Fact]
    public void Disabled_retention_accepts_dormant_values()
    {
        AuthRetentionOptions options = new()
        {
            Enabled = false,
            BatchSize = 0,
        };

        Assert.True(this.validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Enabled_retention_accepts_safe_defaults()
    {
        AuthRetentionOptions options = new() { Enabled = true };

        Assert.True(this.validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Enabled_retention_rejects_unbounded_or_invalid_values()
    {
        AuthRetentionOptions options = new()
        {
            Enabled = true,
            ExpiredExchangeHistoryHours = 0,
            PasswordRecoveryHistoryHours = 0,
            SessionHistoryDays = 0,
            AuthenticationChallengeHistoryHours = 0,
            ExpiredTotpEnrollmentHistoryHours = 0,
            DisabledTotpAuthenticatorHistoryDays = 0,
            MultiFactorFailureHistoryHours = 0,
            AuthenticationFailureHistoryHours = 0,
            BatchSize = 10_001,
            MaxBatchesPerCategoryPerCycle = 0,
            IntervalMinutes = 0,
        };

        ValidateOptionsResult result = this.validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Equal(11, result.Failures.Count());
    }

    [Fact]
    public void Retention_must_cover_active_authentication_attempt_windows()
    {
        AuthRetentionOptions retention = new()
        {
            Enabled = true,
            AuthenticationFailureHistoryHours = 1,
            MultiFactorFailureHistoryHours = 1,
        };
        AuthApplicationOptions application = new()
        {
            FailedLoginWindowMinutes = 61,
            MultiFactor = new AuthMultiFactorOptions
            {
                ManagementAttemptWindowMinutes = 120,
            },
        };

        ValidateOptionsResult result = AuthRetentionOptionsValidator.ValidateCompatibility(
            retention,
            application);

        Assert.True(result.Failed);
        Assert.Equal(2, result.Failures.Count());
    }

    [Fact]
    public void Retention_accepts_attempt_windows_within_the_history_horizon()
    {
        AuthRetentionOptions retention = new()
        {
            Enabled = true,
            AuthenticationFailureHistoryHours = 2,
            MultiFactorFailureHistoryHours = 2,
        };
        AuthApplicationOptions application = new()
        {
            FailedLoginWindowMinutes = 120,
            MultiFactor = new AuthMultiFactorOptions
            {
                ManagementAttemptWindowMinutes = 120,
            },
        };

        Assert.True(AuthRetentionOptionsValidator.ValidateCompatibility(retention, application).Succeeded);
    }
}
