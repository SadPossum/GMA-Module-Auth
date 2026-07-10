namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberDisabledIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-disabled";
    public const int EventVersion = 1;

    public MemberDisabledIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        string reason)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.Reason = IntegrationEventContractGuards.NormalizeRequiredText(
            reason,
            AuthContractLimits.DisableReasonMaxLength,
            nameof(reason));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public string Reason { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
