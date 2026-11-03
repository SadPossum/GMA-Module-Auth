namespace Gma.Modules.Auth.Contracts;

public sealed record MultiFactorStepUpRequest(
    string Password,
    MultiFactorCodeType CodeType,
    string Code,
    string RefreshToken);
