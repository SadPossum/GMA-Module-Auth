namespace Gma.Modules.Auth.Contracts;

public sealed record UnlinkExternalIdentityRequest(string RefreshToken, string? CurrentPassword = null);
