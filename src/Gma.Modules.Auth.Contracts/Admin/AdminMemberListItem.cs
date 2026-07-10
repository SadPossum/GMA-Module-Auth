namespace Gma.Modules.Auth.Contracts;

public sealed record AdminMemberListItem(
    Guid MemberId,
    string ScopeId,
    MemberStatus Status,
    string? ActiveUsername,
    DateTimeOffset RegisteredAtUtc,
    int ActiveSessionCount);
