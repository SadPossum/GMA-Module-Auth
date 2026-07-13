namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Application.Events;
using Gma.Framework.Messaging;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.Enums;

internal sealed class MemberAuthenticationMethodChangedOutboxProjector(IOutboxWriterRegistry outboxWriters)
    : IDomainEventHandler<MemberAuthenticationMethodChangedDomainEvent>
{
    public Task HandleAsync(
        MemberAuthenticationMethodChangedDomainEvent domainEvent,
        CancellationToken cancellationToken) =>
        outboxWriters.GetRequired(AuthModuleMetadata.Name).EnqueueAsync(
            new MemberAuthenticationMethodChangedIntegrationEvent(
                domainEvent.EventId,
                domainEvent.ScopeId,
                domainEvent.OccurredAtUtc,
                domainEvent.MemberId.Value,
                domainEvent.AuthenticationMethod,
                Map(domainEvent.Change)),
            cancellationToken);

    private static AuthenticationMethodChange Map(MemberAuthenticationMethodChange change) =>
        change switch
        {
            MemberAuthenticationMethodChange.Added => AuthenticationMethodChange.Added,
            MemberAuthenticationMethodChange.Updated => AuthenticationMethodChange.Updated,
            MemberAuthenticationMethodChange.Removed => AuthenticationMethodChange.Removed,
            _ => throw new ArgumentOutOfRangeException(nameof(change), change, "Authentication method change is invalid."),
        };
}
