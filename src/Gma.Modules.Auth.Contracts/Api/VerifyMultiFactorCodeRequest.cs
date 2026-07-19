namespace Gma.Modules.Auth.Contracts;

public sealed record VerifyMultiFactorCodeRequest(
    MultiFactorCodeType CodeType,
    string Code,
    string RefreshToken);
