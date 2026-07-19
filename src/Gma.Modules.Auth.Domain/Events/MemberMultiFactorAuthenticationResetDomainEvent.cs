namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberMultiFactorAuthenticationResetDomainEvent : ScopedDomainEvent
{
    public MemberMultiFactorAuthenticationResetDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        string scopeId,
        string actorId,
        string reason)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        this.MemberId = memberId;
        this.ActorId = DomainEventGuards.NormalizeRequiredText(
            actorId,
            MemberTotpAuthenticator.AdministrativeActorIdMaxLength,
            nameof(actorId));
        this.Reason = DomainEventGuards.NormalizeRequiredText(
            reason,
            MemberTotpAuthenticator.AdministrativeResetReasonMaxLength,
            nameof(reason));
    }

    public MemberId MemberId { get; }
    public string ActorId { get; }
    public string Reason { get; }
}
