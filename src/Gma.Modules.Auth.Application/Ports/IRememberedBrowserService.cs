namespace Gma.Modules.Auth.Application.Ports;

using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

// Populated only by the Auth HTTP boundary. Never obtained from a request body.
public sealed class RememberedBrowserRequestContext
{
    public string? DeviceCredential { get; set; }
    public long? ExpectedGeneration { get; set; }
    public bool IsRememberedOperation { get; set; }
    public bool IsBrowserTransport { get; set; }
}

public enum RememberedBrowserOperationKind
{
    Device,
    Remember,
    Select,
    Recover,
    Lock,
    BeginSignIn,
    CancelSignIn,
    Forget,
    ForgetDevice,
    Activity
}

public sealed record RememberedBrowserOperation(
    RememberedBrowserOperationKind Kind,
    Guid OperationId,
    long ExpectedGeneration,
    Guid? MemberId = null,
    Guid? SessionId = null,
    Guid? ProofId = null,
    string? Pin = null,
    string? Label = null,
    bool Consent = false);

// Secrets are transport-only: the endpoint writes HttpOnly cookies, never serializes this result.
public sealed record RememberedBrowserCompletion(
    RememberedBrowserOperationResponse Response,
    string? RefreshToken = null,
    string? DeviceCredential = null,
    DateTimeOffset? CookieExpiresAtUtc = null);

public interface IRememberedBrowserService
{
    Task<RememberedBrowserCurrentResponse> CurrentAsync(CancellationToken cancellationToken);
    Task<RememberedBrowserOperationResponse> OutcomeAsync(Guid operationId, CancellationToken cancellationToken);
    Task<RememberedBrowserCompletion> ExecuteAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken);
    Task<bool> AdmitRefreshAsync(Member member, MemberSessionId sessionId, CancellationToken cancellationToken);
    Task<bool> AdmitChallengeAsync(MemberAuthenticationChallenge challenge, CancellationToken cancellationToken);
}

public sealed class RememberedBrowserStateChangedException : Exception
{
    public RememberedBrowserStateChangedException()
        : base("The remembered browser state changed.")
    {
    }
}
