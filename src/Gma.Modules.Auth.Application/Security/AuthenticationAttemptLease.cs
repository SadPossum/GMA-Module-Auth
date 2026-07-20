namespace Gma.Modules.Auth.Application.Security;

public readonly record struct AuthenticationAttemptLease
{
    public AuthenticationAttemptLease(Guid attemptId, DateTimeOffset acquiredAtUtc)
    {
        if (attemptId == Guid.Empty)
        {
            throw new ArgumentException("Authentication attempt id cannot be empty.", nameof(attemptId));
        }

        this.AttemptId = attemptId;
        this.AcquiredAtUtc = acquiredAtUtc;
    }

    public Guid AttemptId { get; }
    public DateTimeOffset AcquiredAtUtc { get; }
}
