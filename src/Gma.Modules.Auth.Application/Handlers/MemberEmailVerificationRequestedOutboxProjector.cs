namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Application.Events;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Events;

internal sealed class MemberEmailVerificationRequestedOutboxProjector(IOutboxWriterRegistry outboxWriters)
    : IDomainEventHandler<MemberEmailVerificationRequestedDomainEvent>
{
    public Task HandleAsync(
        MemberEmailVerificationRequestedDomainEvent domainEvent,
        CancellationToken cancellationToken) =>
        outboxWriters.GetRequired(AuthModuleMetadata.Name).EnqueueAsync(
            new MemberEmailVerificationRequestedIntegrationEvent(
                domainEvent.EventId,
                domainEvent.ScopeId,
                domainEvent.OccurredAtUtc,
                domainEvent.MemberId.Value,
                domainEvent.Email,
                domainEvent.VerificationCode,
                domainEvent.ExpiresAtUtc),
            cancellationToken);
}
