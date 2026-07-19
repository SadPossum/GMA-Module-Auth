namespace Gma.Modules.Auth.Contracts;

public sealed record CompleteMultiFactorChallengeRequest(
    string ChallengeToken,
    MultiFactorCodeType CodeType,
    string Code);
