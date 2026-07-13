namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberEmailVerifiedIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-email-verified";
    public const int EventVersion = 1;

    public MemberEmailVerifiedIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        string email)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.Email = IntegrationEventContractGuards.NormalizeRequiredText(
            email,
            AuthContractLimits.UsernameMaxLength,
            nameof(email));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public string Email { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
