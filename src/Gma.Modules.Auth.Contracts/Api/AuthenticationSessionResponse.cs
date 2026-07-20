namespace Gma.Modules.Auth.Contracts;

public sealed record AuthenticationSessionResponse(
    Guid SessionId,
    string AuthenticationMethod,
    DateTimeOffset LoginDateTimeUtc,
    DateTimeOffset RefreshTokenExpiresAtUtc,
    DateTimeOffset AbsoluteExpiresAtUtc,
    bool IsCurrent);
