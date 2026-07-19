namespace Gma.Modules.Auth.Contracts;

public sealed record TotpActivationResponse(
    string AccessToken,
    string RefreshToken,
    IReadOnlyList<string> RecoveryCodes);
