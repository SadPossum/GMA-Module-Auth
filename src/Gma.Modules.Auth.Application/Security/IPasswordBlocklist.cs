namespace Gma.Modules.Auth.Application.Security;

public interface IPasswordBlocklist
{
    ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken);
}

internal sealed class CommonPasswordBlocklist : IPasswordBlocklist
{
    private static readonly HashSet<string> Blocked = new(StringComparer.OrdinalIgnoreCase)
    {
        "123456789012345",
        "correcthorsebatterystaple",
        "letmeinletmeinletmein",
        "passwordpassword",
        "qwertyuiopasdfgh",
        "welcome123456789"
    };

    public ValueTask<bool> IsBlockedAsync(string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Blocked.Contains(password));
    }
}
