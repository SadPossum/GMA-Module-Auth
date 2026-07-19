namespace Gma.Modules.Auth.Persistence;

using Microsoft.Extensions.Options;

internal sealed class AuthRetentionOptionsValidator : IValidateOptions<AuthRetentionOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthRetentionOptions options)
    {
        if (!options.Enabled)
        {
            return ValidateOptionsResult.Success;
        }

        List<string> failures = [];
        if (options.ExpiredExchangeHistoryHours is < 1 or > 8_760)
        {
            failures.Add("Auth:Retention:ExpiredExchangeHistoryHours must be between 1 and 8760.");
        }

        if (options.SessionHistoryDays is < 1 or > 3_650)
        {
            failures.Add("Auth:Retention:SessionHistoryDays must be between 1 and 3650.");
        }

        if (options.PasswordRecoveryHistoryHours is < 1 or > 8_760)
        {
            failures.Add("Auth:Retention:PasswordRecoveryHistoryHours must be between 1 and 8760.");
        }

        if (options.AuthenticationChallengeHistoryHours is < 1 or > 8_760)
        {
            failures.Add("Auth:Retention:AuthenticationChallengeHistoryHours must be between 1 and 8760.");
        }

        if (options.ExpiredTotpEnrollmentHistoryHours is < 1 or > 8_760)
        {
            failures.Add("Auth:Retention:ExpiredTotpEnrollmentHistoryHours must be between 1 and 8760.");
        }

        if (options.DisabledTotpAuthenticatorHistoryDays is < 1 or > 3_650)
        {
            failures.Add("Auth:Retention:DisabledTotpAuthenticatorHistoryDays must be between 1 and 3650.");
        }

        if (options.MultiFactorFailureHistoryHours is < 1 or > 8_760)
        {
            failures.Add("Auth:Retention:MultiFactorFailureHistoryHours must be between 1 and 8760.");
        }

        if (options.AuthenticationFailureHistoryHours is < 1 or > 8_760)
        {
            failures.Add("Auth:Retention:AuthenticationFailureHistoryHours must be between 1 and 8760.");
        }

        if (options.BatchSize is < 1 or > 10_000)
        {
            failures.Add("Auth:Retention:BatchSize must be between 1 and 10000.");
        }

        if (options.MaxBatchesPerCategoryPerCycle is < 1 or > 1_000)
        {
            failures.Add("Auth:Retention:MaxBatchesPerCategoryPerCycle must be between 1 and 1000.");
        }

        if (options.IntervalMinutes is < 1 or > 10_080)
        {
            failures.Add("Auth:Retention:IntervalMinutes must be between 1 and 10080.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
