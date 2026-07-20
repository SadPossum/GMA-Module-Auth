namespace Gma.Modules.Auth.Contracts;

public sealed record SetPasswordRequest(
    string NewPassword,
    string RefreshToken,
    string? CurrentPassword = null);
