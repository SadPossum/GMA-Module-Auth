namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Application.Events;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Events;

internal sealed class MemberPasswordRecoveryRequestedOutboxProjector(IOutboxWriterRegistry outboxWriters)
    : IDomainEventHandler<MemberPasswordRecoveryRequestedDomainEvent>
{
    public Task HandleAsync(
        MemberPasswordRecoveryRequestedDomainEvent domainEvent,
        CancellationToken cancellationToken) =>
        outboxWriters.GetRequired(AuthModuleMetadata.Name).EnqueueAsync(
            new MemberPasswordRecoveryRequestedIntegrationEvent(
                domainEvent.EventId,
                domainEvent.ScopeId,
                domainEvent.OccurredAtUtc,
                domainEvent.ChallengeId.Value,
                domainEvent.MemberId.Value,
                domainEvent.Email,
                domainEvent.RecoveryCode,
                domainEvent.ExpiresAtUtc),
            cancellationToken);
}
