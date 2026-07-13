namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Application.Events;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Events;

internal sealed class MemberEmailVerifiedOutboxProjector(IOutboxWriterRegistry outboxWriters)
    : IDomainEventHandler<MemberEmailVerifiedDomainEvent>
{
    public Task HandleAsync(MemberEmailVerifiedDomainEvent domainEvent, CancellationToken cancellationToken) =>
        outboxWriters.GetRequired(AuthModuleMetadata.Name).EnqueueAsync(
            new MemberEmailVerifiedIntegrationEvent(
                domainEvent.EventId,
                domainEvent.ScopeId,
                domainEvent.OccurredAtUtc,
                domainEvent.MemberId.Value,
                domainEvent.Email),
            cancellationToken);
}
