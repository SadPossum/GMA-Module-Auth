namespace Gma.Modules.Auth.Application;

using Microsoft.Extensions.Options;

internal sealed class AuthApplicationOptionsValidator : IValidateOptions<AuthApplicationOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthApplicationOptions options)
    {
        if (options.SelfRegistration is null)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:SelfRegistration must be configured.");
        }

        if (options.MultiFactor is null)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:MultiFactor must be configured.");
        }

        if (options.MultiFactor.EnrollmentLifetimeMinutes is < 1 or > 60 ||
            options.MultiFactor.ChallengeLifetimeMinutes is < 1 or > 30 ||
            options.MultiFactor.ChallengeMaximumAttempts is < 1 or > 20 ||
            options.MultiFactor.RecoveryCodeCount is < 1 or > Domain.Aggregates.MemberTotpAuthenticator.RecoveryCodeLimit ||
            options.MultiFactor.SensitiveSessionFreshnessMinutes is < 1 or > 60 ||
            options.MultiFactor.ManagementMaximumAttempts is < 1 or > 20 ||
            options.MultiFactor.ManagementAttemptWindowMinutes is < 1 or > 1_440)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:MultiFactor settings are outside their supported ranges.");
        }

        if (options.RefreshTokenLifetimeDays is < 1 or > 3_650)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:RefreshTokenLifetimeDays must be between 1 and 3650.");
        }

        if (options.SessionAbsoluteLifetimeDays is < 1 or > 3_650 ||
            options.SessionAbsoluteLifetimeDays < options.RefreshTokenLifetimeDays)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:SessionAbsoluteLifetimeDays must be between " +
                "RefreshTokenLifetimeDays and 3650.");
        }

        if (options.MaximumActiveSessionsPerMember is < 1 or > 1_000)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:MaximumActiveSessionsPerMember must be between 1 and 1000.");
        }

        if (options.FailedLoginLimit is < 1 or > 100)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:FailedLoginLimit must be between 1 and 100.");
        }

        if (options.FailedLoginWindowMinutes is < 1 or > 1_440)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:FailedLoginWindowMinutes must be between 1 and 1440.");
        }

        if (options.ExternalExchangeLifetimeMinutes is < 1 or > 30)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:ExternalExchangeLifetimeMinutes must be between 1 and 30.");
        }

        if (options.ExternalLinkSessionFreshnessMinutes is < 1 or > 60)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:ExternalLinkSessionFreshnessMinutes must be between 1 and 60.");
        }

        if (options.EmailVerificationLifetimeMinutes is < 5 or > 10_080)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:EmailVerificationLifetimeMinutes must be between 5 and 10080.");
        }

        if (options.EmailVerificationRequestCooldownSeconds is < 1 or > 3_600)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:EmailVerificationRequestCooldownSeconds must be between 1 and 3600.");
        }

        if (options.PasswordRecoveryLifetimeMinutes is < 5 or > 1_440)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:PasswordRecoveryLifetimeMinutes must be between 5 and 1440.");
        }

        if (options.PasswordRecoveryRequestCooldownSeconds is < 1 or > 3_600)
        {
            return ValidateOptionsResult.Fail(
                $"{AuthApplicationOptions.SectionName}:PasswordRecoveryRequestCooldownSeconds must be between 1 and 3600.");
        }

        return ValidateOptionsResult.Success;
    }
}
