namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Application.Events;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Events;

internal sealed class MemberAuthenticatedOutboxProjector(IOutboxWriterRegistry outboxWriters)
    : IDomainEventHandler<MemberAuthenticatedDomainEvent>
{
    public Task HandleAsync(MemberAuthenticatedDomainEvent domainEvent, CancellationToken cancellationToken) =>
        outboxWriters.GetRequired(AuthModuleMetadata.Name).EnqueueAsync(
            new MemberAuthenticatedIntegrationEvent(
                domainEvent.EventId,
                domainEvent.ScopeId,
                domainEvent.OccurredAtUtc,
                domainEvent.MemberId.Value,
                domainEvent.SessionId.Value,
                domainEvent.AuthenticationMethod,
                domainEvent.IpAddress,
                domainEvent.UserAgent),
            cancellationToken);
}
