namespace Gma.Modules.Auth.Domain.Events;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Framework.Domain;

public sealed record MemberDisabledDomainEvent : ScopedDomainEvent
{
    public MemberDisabledDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        string scopeId,
        string reason)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        this.MemberId = memberId;
        this.Reason = DomainEventGuards.NormalizeRequiredText(reason, Member.DisabledReasonMaxLength, nameof(reason));
    }

    public MemberId MemberId { get; }
    public string Reason { get; }
}
