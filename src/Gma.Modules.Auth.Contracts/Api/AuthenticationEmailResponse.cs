namespace Gma.Modules.Auth.Contracts;

public sealed record AuthenticationEmailResponse(
    Guid Id,
    string Email,
    bool IsActive,
    bool IsVerified,
    DateTimeOffset? VerifiedAtUtc);
