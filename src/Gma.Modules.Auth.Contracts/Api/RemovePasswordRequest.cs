namespace Gma.Modules.Auth.Contracts;

public sealed record RemovePasswordRequest(string CurrentPassword, string RefreshToken);
