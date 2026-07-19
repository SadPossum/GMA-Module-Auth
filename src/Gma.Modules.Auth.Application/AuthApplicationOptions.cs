namespace Gma.Modules.Auth.Application;

public sealed class AuthApplicationOptions
{
    public const string SectionName = "Auth";

    public AuthSelfRegistrationOptions SelfRegistration { get; set; } = new();
    public AuthMultiFactorOptions MultiFactor { get; set; } = new();
    public int RefreshTokenLifetimeDays { get; set; } = 30;
    public int FailedLoginLimit { get; set; } = 5;
    public int FailedLoginWindowMinutes { get; set; } = 15;
    public int ExternalExchangeLifetimeMinutes { get; set; } = 5;
    public int ExternalLinkSessionFreshnessMinutes { get; set; } = 10;
    public int EmailVerificationLifetimeMinutes { get; set; } = 1_440;
    public int EmailVerificationRequestCooldownSeconds { get; set; } = 60;
    public int PasswordRecoveryLifetimeMinutes { get; set; } = 30;
    public int PasswordRecoveryRequestCooldownSeconds { get; set; } = 60;
}
