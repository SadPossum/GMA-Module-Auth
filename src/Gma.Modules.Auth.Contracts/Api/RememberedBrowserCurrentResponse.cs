namespace Gma.Modules.Auth.Contracts;

public sealed record RememberedBrowserCurrentResponse(
    RememberedBrowserState State,
    long Generation,
    int PinDigits,
    IReadOnlyList<RememberedBrowserAccount> Accounts,
    RememberedBrowserActiveAccount? Active,
    DateTimeOffset? IdleExpiresAtUtc,
    DateTimeOffset? AbsoluteExpiresAtUtc,
    string? CsrfToken = null);
