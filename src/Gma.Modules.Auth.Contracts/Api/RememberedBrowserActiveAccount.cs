namespace Gma.Modules.Auth.Contracts;

public sealed record RememberedBrowserActiveAccount(
    Guid MemberId,
    Guid SessionId,
    Guid? ProofId,
    string Username,
    string? Label);
