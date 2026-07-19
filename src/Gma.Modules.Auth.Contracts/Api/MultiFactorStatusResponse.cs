namespace Gma.Modules.Auth.Contracts;

public sealed record MultiFactorStatusResponse(
    bool ProviderAvailable,
    bool IsPending,
    bool IsActive,
    int UnusedRecoveryCodeCount,
    DateTimeOffset? EnrollmentExpiresAtUtc,
    DateTimeOffset? ActivatedAtUtc,
    DateTimeOffset? RecoveryCodesRegeneratedAtUtc);
