namespace Gma.Modules.Auth.Contracts;

public sealed record BrowserTotpActivationResponse(
    string AccessToken,
    IReadOnlyList<string> RecoveryCodes);
