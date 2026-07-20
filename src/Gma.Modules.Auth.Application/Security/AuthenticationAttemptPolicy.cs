namespace Gma.Modules.Auth.Application.Security;

public sealed record AuthenticationAttemptPolicy
{
    public const int MaximumSupportedAttempts = 10_000;
    public static readonly TimeSpan MaximumSupportedWindow = TimeSpan.FromDays(30);

    public AuthenticationAttemptPolicy(int maximumAttempts, TimeSpan window)
    {
        if (maximumAttempts is < 1 or > MaximumSupportedAttempts)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumAttempts),
                maximumAttempts,
                $"Maximum attempts must be between 1 and {MaximumSupportedAttempts}.");
        }

        if (window <= TimeSpan.Zero || window > MaximumSupportedWindow)
        {
            throw new ArgumentOutOfRangeException(
                nameof(window),
                window,
                $"Attempt window must be positive and at most {MaximumSupportedWindow.TotalDays} days.");
        }

        this.MaximumAttempts = maximumAttempts;
        this.Window = window;
    }

    public int MaximumAttempts { get; }
    public TimeSpan Window { get; }
}
