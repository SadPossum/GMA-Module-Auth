namespace Gma.Modules.Auth.Application.Security;

using Gma.Modules.Auth.Domain.Services;

internal sealed class PasswordProofService(
    IPasswordHashingService passwordHashingService,
    IAuthenticationAttemptLimiter attemptLimiter)
{
    public async ValueTask<PasswordVerificationOutcome> VerifyAsync(
        string scopeId,
        string purpose,
        string target,
        string? passwordHash,
        string password,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        if (!await attemptLimiter.IsAllowedAsync(
                scopeId,
                purpose,
                target,
                nowUtc,
                cancellationToken).ConfigureAwait(false))
        {
            return PasswordVerificationOutcome.Unknown;
        }

        PasswordVerificationOutcome outcome;
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            _ = passwordHashingService.HashPassword(password);
            outcome = PasswordVerificationOutcome.Unknown;
        }
        else
        {
            outcome = passwordHashingService.VerifyPassword(passwordHash, password);
        }

        if (outcome == PasswordVerificationOutcome.Unknown)
        {
            await attemptLimiter.RecordFailureAsync(
                scopeId,
                purpose,
                target,
                nowUtc,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await attemptLimiter.RecordSuccessAsync(
                scopeId,
                purpose,
                target,
                cancellationToken).ConfigureAwait(false);
        }

        return outcome;
    }
}
