namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberEnabledIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-enabled";
    public const int EventVersion = 1;

    public MemberEnabledIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
