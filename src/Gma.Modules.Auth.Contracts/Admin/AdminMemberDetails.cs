namespace Gma.Modules.Auth.Contracts;

public sealed record AdminMemberDetails(
    Guid MemberId,
    string ScopeId,
    MemberStatus Status,
    string? ActiveUsername,
    DateTimeOffset RegisteredAtUtc,
    DateTimeOffset? DisabledAtUtc,
    string? DisabledReason,
    int ActiveSessionCount,
    int TotalSessionCount,
    bool HasPassword = true,
    bool HasVerifiedEmail = false,
    IReadOnlyList<string>? ExternalProviders = null,
    bool HasActiveTotpAuthenticator = false,
    int UnusedTotpRecoveryCodeCount = 0,
    DateTimeOffset? TotpActivatedAtUtc = null);
