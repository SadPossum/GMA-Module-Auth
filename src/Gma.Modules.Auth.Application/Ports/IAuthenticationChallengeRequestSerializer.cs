namespace Gma.Modules.Auth.Application.Ports;

using Gma.Modules.Auth.Domain.ValueObjects;

public interface IAuthenticationChallengeRequestSerializer
{
    Task AcquireAsync(
        string scopeId,
        MemberId memberId,
        CancellationToken cancellationToken);
}
