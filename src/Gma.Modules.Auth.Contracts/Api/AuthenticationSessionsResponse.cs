namespace Gma.Modules.Auth.Contracts;

public sealed record AuthenticationSessionsResponse(IReadOnlyCollection<AuthenticationSessionResponse> Sessions);
