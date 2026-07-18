namespace Gma.Modules.Auth.Contracts;

public sealed record ConfirmPasswordRecoveryRequest(string Code, string NewPassword);
