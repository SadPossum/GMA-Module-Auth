namespace Gma.Modules.Auth.Contracts;

public enum RememberedBrowserState
{
    Missing = 0,
    Locked = 1,
    Active = 2,
    SigningIn = 3,
    Revoked = 4,
    Unavailable = 5
}

public enum RememberedBrowserOutcome
{
    Applied = 0,
    StateChanged = 1,
    AuthenticationRequired = 2,
    PinRejected = 3,
    RateLimited = 4,
    SessionLimitReached = 5,
    Unavailable = 6,
    NotFound = 7
}

public sealed record RememberedBrowserAccount(
    Guid ProofId,
    string Username,
    string? Label,
    DateTimeOffset ExpiresAtUtc,
    bool RequiresSignIn,
    string? DisplayName = null,
    string? JobTitle = null);

public sealed record RememberedBrowserActiveAccount(
    Guid MemberId,
    Guid SessionId,
    Guid? ProofId,
    string Username,
    string? Label);

public sealed record RememberedBrowserCurrentResponse(
    RememberedBrowserState State,
    long Generation,
    int PinDigits,
    IReadOnlyList<RememberedBrowserAccount> Accounts,
    RememberedBrowserActiveAccount? Active,
    DateTimeOffset? IdleExpiresAtUtc,
    DateTimeOffset? AbsoluteExpiresAtUtc,
    string? CsrfToken = null);

public sealed record RememberedBrowserOperationResponse(
    RememberedBrowserOutcome Outcome,
    RememberedBrowserCurrentResponse Current,
    string? AccessToken = null);

public sealed record RememberBrowserAccountRequest(
    Guid OperationId,
    long ExpectedGeneration,
    string Pin,
    string? Label,
    bool Consent);

public sealed record SelectRememberedAccountRequest(
    Guid OperationId,
    long ExpectedGeneration,
    Guid ProofId,
    string Pin);

public sealed record RecoverRememberedOperationRequest(
    Guid OperationId,
    long ExpectedGeneration,
    string Pin);

public sealed record RememberedBrowserTransitionRequest(Guid OperationId, long ExpectedGeneration);

public sealed record ForgetRememberedAccountRequest(Guid OperationId, long ExpectedGeneration, Guid ProofId);

public sealed record RememberedBrowserActivityRequest(long ExpectedGeneration, Guid SessionId);
