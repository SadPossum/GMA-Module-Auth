namespace Gma.Modules.Auth.Application.Security;

using System.Collections.Concurrent;

public sealed class ProcessLocalAuthenticationAttemptLimiter : IAuthenticationAttemptLimiter
{
    public const int DefaultMaximumPartitions = 50_000;

    private readonly ConcurrentDictionary<string, FailureWindow> failures = new(StringComparer.Ordinal);
    private readonly Lock partitionGate = new();
    private readonly int maximumPartitions;

    public ProcessLocalAuthenticationAttemptLimiter()
        : this(DefaultMaximumPartitions)
    {
    }

    internal ProcessLocalAuthenticationAttemptLimiter(int maximumPartitions)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumPartitions, 1);
        this.maximumPartitions = maximumPartitions;
    }

    internal int PartitionCount => this.failures.Count;

    public ValueTask<AuthenticationAttemptLease?> TryAcquireAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        AuthenticationAttemptPolicy policy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();
        string key = AuthenticationAttemptPartition.Create(scopeId, purpose, target).Key;
        DateTimeOffset cutoffUtc = nowUtc.Subtract(policy.Window);
        AuthenticationAttemptLease lease = new(Guid.CreateVersion7(), nowUtc);
        while (true)
        {
            if (!this.failures.TryGetValue(key, out FailureWindow? current))
            {
                lock (this.partitionGate)
                {
                    if (this.failures.ContainsKey(key))
                    {
                        continue;
                    }

                    this.PruneExpiredPartitions(nowUtc);
                    if (this.failures.Count >= this.maximumPartitions)
                    {
                        return ValueTask.FromResult<AuthenticationAttemptLease?>(null);
                    }

                    if (this.failures.TryAdd(key, FailureWindow.Create(lease, policy.Window)))
                    {
                        return ValueTask.FromResult<AuthenticationAttemptLease?>(lease);
                    }
                }

                continue;
            }

            FailureWindow updated = current.TryAcquire(
                lease,
                cutoffUtc,
                policy.Window,
                policy.MaximumAttempts,
                out bool acquired);
            if (this.failures.TryUpdate(key, updated, current))
            {
                return ValueTask.FromResult<AuthenticationAttemptLease?>(acquired ? lease : null);
            }
        }
    }

    public ValueTask RecordSuccessAsync(
        string scopeId,
        string purpose,
        string target,
        AuthenticationAttemptLease lease,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string key = AuthenticationAttemptPartition.Create(scopeId, purpose, target).Key;
        while (this.failures.TryGetValue(key, out FailureWindow? current))
        {
            FailureWindow updated = current.ClearSucceeded(lease);
            bool updatedSuccessfully = updated.IsEmpty
                ? this.failures.TryRemove(new KeyValuePair<string, FailureWindow>(key, current))
                : this.failures.TryUpdate(key, updated, current);
            if (updatedSuccessfully)
            {
                break;
            }
        }

        return ValueTask.CompletedTask;
    }

    private void PruneExpiredPartitions(DateTimeOffset nowUtc)
    {
        foreach ((string key, FailureWindow window) in this.failures)
        {
            if (window.CanEvict(nowUtc))
            {
                this.failures.TryRemove(new KeyValuePair<string, FailureWindow>(key, window));
            }
        }
    }

    private sealed class FailureWindow(AttemptReservation[] attempts)
    {
        public bool IsEmpty => attempts.Length == 0;

        public static FailureWindow Create(AuthenticationAttemptLease lease, TimeSpan window) =>
            new([new AttemptReservation(lease.AttemptId, lease.AcquiredAtUtc, lease.AcquiredAtUtc.Add(window))]);

        public bool CanEvict(DateTimeOffset nowUtc) => attempts.All(item => item.ExpiresAtUtc <= nowUtc);

        public FailureWindow TryAcquire(
            AuthenticationAttemptLease lease,
            DateTimeOffset cutoffUtc,
            TimeSpan window,
            int maximumAttempts,
            out bool acquired)
        {
            AttemptReservation[] retained = [.. attempts
                .Where(item => item.AttemptedAtUtc > cutoffUtc)
                .OrderBy(item => item.AttemptedAtUtc)];
            acquired = retained.Length < maximumAttempts;
            return acquired
                ? new FailureWindow([.. retained, new AttemptReservation(
                    lease.AttemptId,
                    lease.AcquiredAtUtc,
                    lease.AcquiredAtUtc.Add(window))])
                : retained.Length == attempts.Length
                    ? this
                    : new FailureWindow(retained);
        }

        public FailureWindow ClearSucceeded(AuthenticationAttemptLease lease) =>
            new([.. attempts.Where(item =>
                item.AttemptedAtUtc > lease.AcquiredAtUtc ||
                (item.AttemptedAtUtc == lease.AcquiredAtUtc && item.AttemptId != lease.AttemptId))]);
    }

    private sealed record AttemptReservation(
        Guid AttemptId,
        DateTimeOffset AttemptedAtUtc,
        DateTimeOffset ExpiresAtUtc);
}
