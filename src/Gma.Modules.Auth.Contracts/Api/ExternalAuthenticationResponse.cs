namespace Gma.Modules.Auth.Contracts;

public sealed record ExternalAuthenticationResponse(
    ExternalAuthenticationStatus Status,
    string ProviderCode,
    string? AccessToken = null,
    string? RefreshToken = null,
    Guid? ExternalIdentityId = null,
    MultiFactorChallengeResponse? MultiFactorChallenge = null);
