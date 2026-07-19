namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Application.Events;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Events;

internal sealed class MemberMultiFactorAuthenticationResetOutboxProjector(IOutboxWriterRegistry outboxWriters)
    : IDomainEventHandler<MemberMultiFactorAuthenticationResetDomainEvent>
{
    public Task HandleAsync(
        MemberMultiFactorAuthenticationResetDomainEvent domainEvent,
        CancellationToken cancellationToken) =>
        outboxWriters.GetRequired(AuthModuleMetadata.Name).EnqueueAsync(
            new MemberMultiFactorAuthenticationResetIntegrationEvent(
                domainEvent.EventId,
                domainEvent.ScopeId,
                domainEvent.OccurredAtUtc,
                domainEvent.MemberId.Value,
                domainEvent.ActorId,
                domainEvent.Reason),
            cancellationToken);
}
