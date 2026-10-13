namespace Gma.Modules.Auth.Contracts;

public sealed record BrowserMultiFactorStepUpRequest(
    string Password,
    MultiFactorCodeType CodeType,
    string Code);
