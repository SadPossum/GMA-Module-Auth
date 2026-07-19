namespace Gma.Modules.Auth.Contracts;

public sealed record PasswordStepUpRequest(string Password, string RefreshToken);
