namespace Gma.Modules.Auth.Contracts;

public sealed record AuthenticationMethodsResponse(
    bool HasPassword,
    IReadOnlyList<AuthenticationEmailResponse> Emails,
    IReadOnlyList<ExternalIdentityResponse> ExternalIdentities);
