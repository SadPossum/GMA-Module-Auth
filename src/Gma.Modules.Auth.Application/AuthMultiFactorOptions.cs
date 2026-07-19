namespace Gma.Modules.Auth.Application;

public sealed class AuthMultiFactorOptions
{
    public int EnrollmentLifetimeMinutes { get; set; } = 10;
    public int ChallengeLifetimeMinutes { get; set; } = 5;
    public int ChallengeMaximumAttempts { get; set; } = 5;
    public int RecoveryCodeCount { get; set; } = 10;
    public int SensitiveSessionFreshnessMinutes { get; set; } = 10;
    public int ManagementMaximumAttempts { get; set; } = 5;
    public int ManagementAttemptWindowMinutes { get; set; } = 15;
}
