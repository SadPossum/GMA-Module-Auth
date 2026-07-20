namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.ValueObjects;

internal sealed class NoOpAuthenticationChallengeRequestSerializer : IAuthenticationChallengeRequestSerializer
{
    public Task AcquireAsync(
        string scopeId,
        MemberId memberId,
        CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
