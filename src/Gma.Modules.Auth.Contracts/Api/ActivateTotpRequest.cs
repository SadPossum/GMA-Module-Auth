namespace Gma.Modules.Auth.Contracts;

public sealed record ActivateTotpRequest(string Code, string RefreshToken);
