namespace Gma.Modules.Auth.Contracts;

public sealed record SetPasswordRequest(string NewPassword, string? CurrentPassword = null);
