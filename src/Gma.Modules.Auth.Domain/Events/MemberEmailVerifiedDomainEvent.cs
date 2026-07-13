namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberEmailVerifiedDomainEvent : ScopedDomainEvent
{
    public MemberEmailVerifiedDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        string scopeId,
        string email)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        this.MemberId = memberId;
        this.Email = DomainEventGuards.NormalizeRequiredText(email, MemberUsername.ValueMaxLength, nameof(email));
    }

    public MemberId MemberId { get; }
    public string Email { get; }
}
