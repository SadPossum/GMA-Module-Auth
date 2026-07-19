namespace Gma.Modules.Auth.Contracts;

public sealed record MultiFactorChallengeResponse(
    string ChallengeToken,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<MultiFactorCodeType> AvailableCodeTypes);
