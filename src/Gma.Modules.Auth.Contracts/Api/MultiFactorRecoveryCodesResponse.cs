namespace Gma.Modules.Auth.Contracts;

public sealed record MultiFactorRecoveryCodesResponse(
    string AccessToken,
    string RefreshToken,
    IReadOnlyList<string> RecoveryCodes);
