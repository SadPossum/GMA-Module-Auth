namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberRegisteredIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-registered";
    public const int EventVersion = 1;

    public MemberRegisteredIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        string username)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.Username = IntegrationEventContractGuards.NormalizeRequiredText(
            username,
            AuthContractLimits.UsernameMaxLength,
            nameof(username));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public string Username { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
