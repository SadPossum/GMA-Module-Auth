namespace Gma.Modules.Auth.Contracts;

public sealed record RememberedBrowserAccount(
    Guid ProofId,
    string Username,
    string? Label,
    DateTimeOffset ExpiresAtUtc,
    bool RequiresSignIn,
    string? DisplayName = null,
    string? JobTitle = null);
