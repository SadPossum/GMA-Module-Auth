namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberMultiFactorAuthenticationResetIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-multi-factor-authentication-reset";
    public const int EventVersion = 1;

    public MemberMultiFactorAuthenticationResetIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        string actorId,
        string reason)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.ActorId = IntegrationEventContractGuards.NormalizeRequiredText(
            actorId,
            AuthContractLimits.AdministrativeActorIdMaxLength,
            nameof(actorId));
        this.Reason = IntegrationEventContractGuards.NormalizeRequiredText(
            reason,
            AuthContractLimits.MultiFactorResetReasonMaxLength,
            nameof(reason));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public string ActorId { get; }
    public string Reason { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
