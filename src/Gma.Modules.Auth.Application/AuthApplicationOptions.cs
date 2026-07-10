namespace Gma.Modules.Auth.Application;

public sealed class AuthApplicationOptions
{
    public const string SectionName = "Auth";

    public int RefreshTokenLifetimeDays { get; set; } = 30;
    public int FailedLoginLimit { get; set; } = 5;
    public int FailedLoginWindowMinutes { get; set; } = 15;
}
