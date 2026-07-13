namespace Gma.Modules.Auth.Contracts;

public sealed record UnlinkExternalIdentityRequest(string? CurrentPassword = null);
