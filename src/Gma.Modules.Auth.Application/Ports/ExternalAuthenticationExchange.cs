namespace Gma.Modules.Auth.Application.Ports;

using Gma.Modules.Auth.Application.ExternalAuthentication;

public sealed record ExternalAuthenticationExchange(
    Guid Id,
    string ScopeId,
    string CodeHash,
    ExternalAuthenticationIntent Intent,
    string ProviderCode,
    string Issuer,
    string Subject,
    string? Email,
    bool EmailVerified,
    Guid? TargetMemberId,
    Guid? TargetSessionId,
    string ReturnUrl,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset? ConsumedAtUtc = null);
