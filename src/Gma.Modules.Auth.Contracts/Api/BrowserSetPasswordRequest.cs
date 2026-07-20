namespace Gma.Modules.Auth.Contracts;

public sealed record BrowserSetPasswordRequest(string NewPassword, string? CurrentPassword = null);
