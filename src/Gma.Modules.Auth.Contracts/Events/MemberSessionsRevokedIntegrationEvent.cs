namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberSessionsRevokedIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-sessions-revoked";
    public const int EventVersion = 1;

    public MemberSessionsRevokedIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        int revokedSessionCount)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.RevokedSessionCount = IntegrationEventContractGuards.RequireNonNegative(
            revokedSessionCount,
            nameof(revokedSessionCount));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public int RevokedSessionCount { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
