namespace Gma.Modules.Auth.Application.Security;

using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

internal sealed class InMemoryAuthenticationAttemptLimiter(IOptions<AuthApplicationOptions> options)
    : IAuthenticationAttemptLimiter
{
    private readonly ConcurrentDictionary<string, FailureWindow> failures = new(StringComparer.Ordinal);

    public bool IsAllowed(string scopeId, string username, DateTimeOffset nowUtc)
    {
        string key = CreateKey(scopeId, username);
        if (!this.failures.TryGetValue(key, out FailureWindow? window))
        {
            return true;
        }

        if (window.StartedAtUtc.AddMinutes(options.Value.FailedLoginWindowMinutes) <= nowUtc)
        {
            this.failures.TryRemove(key, out _);
            return true;
        }

        return window.Count < options.Value.FailedLoginLimit;
    }

    public void RecordFailure(string scopeId, string username, DateTimeOffset nowUtc)
    {
        string key = CreateKey(scopeId, username);
        this.failures.AddOrUpdate(
            key,
            _ => new FailureWindow(nowUtc, 1),
            (_, current) => current.StartedAtUtc.AddMinutes(options.Value.FailedLoginWindowMinutes) <= nowUtc
                ? new FailureWindow(nowUtc, 1)
                : current with { Count = current.Count + 1 });
    }

    public void RecordSuccess(string scopeId, string username) =>
        this.failures.TryRemove(CreateKey(scopeId, username), out _);

    private static string CreateKey(string scopeId, string username) =>
        $"{scopeId.Trim().ToLowerInvariant()}\n{username.Trim().ToLowerInvariant()}";

    private sealed record FailureWindow(DateTimeOffset StartedAtUtc, int Count);
}
