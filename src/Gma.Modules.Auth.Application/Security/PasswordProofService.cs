namespace Gma.Modules.Auth.Application.Security;

using Gma.Modules.Auth.Domain.Services;
using Gma.Framework.Observability;
using Microsoft.Extensions.Options;

internal sealed class PasswordProofService(
    IPasswordHashingService passwordHashingService,
    IAuthenticationAttemptLimiter attemptLimiter,
    IOptions<AuthApplicationOptions> options,
    ISecuritySignalRecorder? securitySignals = null)
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
        AuthenticationAttemptPolicy policy = new(
            options.Value.FailedLoginLimit,
            TimeSpan.FromMinutes(options.Value.FailedLoginWindowMinutes));
        AuthenticationAttemptLease? lease = await attemptLimiter.TryAcquireAsync(
                scopeId,
                purpose,
                target,
                nowUtc,
                policy,
                cancellationToken).ConfigureAwait(false);
        if (lease is null)
        {
            securitySignals?.Record(
                AuthSecuritySignalDefinitions.PasswordProofRateLimited);
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

        if (outcome != PasswordVerificationOutcome.Unknown)
        {
            await attemptLimiter.RecordSuccessAsync(
                scopeId,
                purpose,
                target,
                lease.Value,
                cancellationToken).ConfigureAwait(false);
        }

        return outcome;
    }
}
