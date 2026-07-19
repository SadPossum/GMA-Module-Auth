namespace Gma.Modules.Auth.Contracts;

public sealed record BrowserVerifyMultiFactorCodeRequest(
    MultiFactorCodeType CodeType,
    string Code);
