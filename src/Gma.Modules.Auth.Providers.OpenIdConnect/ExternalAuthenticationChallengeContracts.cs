namespace Gma.Modules.Auth.Providers.OpenIdConnect;

public sealed record ExternalAuthenticationProviderListResponse(IReadOnlyList<string> Providers);

public sealed record ExternalAuthenticationChallengeRequest(string ReturnUrl);

public sealed record ExternalAuthenticationChallengeResponse(string StartUrl);
