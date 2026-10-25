namespace Gma.Modules.Auth.Persistence.Remembered;

using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;

// Keep disabled hosts constructible without dropping the refresh/challenge
// checks for credentials retained from a previously enabled browser runtime.
internal sealed class DisabledRememberedBrowserService(IOptions<RememberedBrowserOptions> options)
    : IRememberedBrowserService
{
    public Task<RememberedBrowserCurrentResponse> CurrentAsync(CancellationToken cancellationToken) =>
        Task.FromResult(this.Unavailable());

    public Task<RememberedBrowserOperationResponse> OutcomeAsync(Guid operationId, CancellationToken cancellationToken) =>
        Task.FromResult(new RememberedBrowserOperationResponse(RememberedBrowserOutcome.Unavailable, this.Unavailable()));

    public Task<RememberedBrowserCompletion> ExecuteAsync(RememberedBrowserOperation operation, CancellationToken cancellationToken) =>
        Task.FromResult(new RememberedBrowserCompletion(new(RememberedBrowserOutcome.Unavailable, this.Unavailable())));

    public Task<bool> AdmitRefreshAsync(Member member, MemberSessionId sessionId, CancellationToken cancellationToken) =>
        Task.FromResult(member.Sessions.Any(session => session.Id == sessionId && session.RememberedBrowserDeviceId is null));

    public Task<bool> AdmitChallengeAsync(MemberAuthenticationChallenge challenge, CancellationToken cancellationToken) =>
        Task.FromResult(challenge.RememberedBrowserDeviceId is null);

    private RememberedBrowserCurrentResponse Unavailable() =>
        new(RememberedBrowserState.Unavailable, 0, options.Value.PinDigits, [], null, null, null);
}
