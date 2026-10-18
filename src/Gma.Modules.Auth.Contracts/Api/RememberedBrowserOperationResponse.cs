namespace Gma.Modules.Auth.Contracts;

public sealed record RememberedBrowserOperationResponse(
    RememberedBrowserOutcome Outcome,
    RememberedBrowserCurrentResponse Current,
    string? AccessToken = null);
