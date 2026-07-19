namespace Gma.Modules.Auth.Contracts;

public sealed record BrowserMultiFactorRecoveryCodesResponse(
    string AccessToken,
    IReadOnlyList<string> RecoveryCodes);
