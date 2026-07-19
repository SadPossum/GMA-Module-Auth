namespace Gma.Modules.Auth.Application.Security;

using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

public sealed class ProcessLocalAuthenticationAttemptLimiter(IOptions<AuthApplicationOptions> options)
    : IAuthenticationAttemptLimiter
{
    private readonly ConcurrentDictionary<string, FailureWindow> failures = new(StringComparer.Ordinal);

    public ValueTask<bool> IsAllowedAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string key = CreateKey(scopeId, purpose, target);
        if (!this.failures.TryGetValue(key, out FailureWindow? window))
        {
            return ValueTask.FromResult(true);
        }

        DateTimeOffset cutoffUtc = nowUtc.AddMinutes(-options.Value.FailedLoginWindowMinutes);
        while (true)
        {
            FailureWindow current = window;
            FailureWindow pruned = current.Prune(cutoffUtc);
            if (pruned.Count == 0)
            {
                if (this.failures.TryRemove(new KeyValuePair<string, FailureWindow>(key, current)))
                {
                    return ValueTask.FromResult(true);
                }
            }
            else if (ReferenceEquals(pruned, current) || this.failures.TryUpdate(key, pruned, current))
            {
                return ValueTask.FromResult(pruned.Count < options.Value.FailedLoginLimit);
            }

            if (!this.failures.TryGetValue(key, out window))
            {
                return ValueTask.FromResult(true);
            }
        }
    }

    public ValueTask RecordFailureAsync(
        string scopeId,
        string purpose,
        string target,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string key = CreateKey(scopeId, purpose, target);
        DateTimeOffset cutoffUtc = nowUtc.AddMinutes(-options.Value.FailedLoginWindowMinutes);
        this.failures.AddOrUpdate(
            key,
            _ => FailureWindow.Create(nowUtc),
            (_, current) => current.Add(nowUtc, cutoffUtc, options.Value.FailedLoginLimit));
        return ValueTask.CompletedTask;
    }

    public ValueTask RecordSuccessAsync(
        string scopeId,
        string purpose,
        string target,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        this.failures.TryRemove(CreateKey(scopeId, purpose, target), out _);
        return ValueTask.CompletedTask;
    }

    private static string CreateKey(string scopeId, string purpose, string target) =>
        $"{scopeId.Trim().ToLowerInvariant()}\n{purpose.Trim().ToLowerInvariant()}\n{target.Trim().ToUpperInvariant()}";

    private sealed class FailureWindow(DateTimeOffset[] failures)
    {
        public int Count => failures.Length;

        public static FailureWindow Create(DateTimeOffset failedAtUtc) => new([failedAtUtc]);

        public FailureWindow Add(DateTimeOffset failedAtUtc, DateTimeOffset cutoffUtc, int limit) =>
            new([.. failures
                .Where(item => item > cutoffUtc)
                .Append(failedAtUtc)
                .Order()
                .TakeLast(limit)]);

        public FailureWindow Prune(DateTimeOffset cutoffUtc)
        {
            int firstRetainedIndex = Array.FindIndex(failures, item => item > cutoffUtc);
            return firstRetainedIndex switch
            {
                0 => this,
                < 0 => new FailureWindow([]),
                _ => new FailureWindow(failures[firstRetainedIndex..]),
            };
        }
    }
}
