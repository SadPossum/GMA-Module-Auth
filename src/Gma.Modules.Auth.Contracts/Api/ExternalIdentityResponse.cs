namespace Gma.Modules.Auth.Contracts;

public sealed record ExternalIdentityResponse(
    Guid Id,
    string ProviderCode,
    DateTimeOffset LinkedAtUtc,
    DateTimeOffset? LastAuthenticatedAtUtc);
