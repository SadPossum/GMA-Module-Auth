namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberEmailVerificationRequestedDomainEvent : ScopedDomainEvent
{
    public MemberEmailVerificationRequestedDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        string scopeId,
        string email,
        string verificationCode,
        DateTimeOffset expiresAtUtc)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        this.MemberId = memberId;
        this.Email = DomainEventGuards.NormalizeRequiredText(email, MemberUsername.ValueMaxLength, nameof(email));
        this.VerificationCode = DomainEventGuards.NormalizeRequiredText(
            verificationCode,
            MemberSession.RefreshTokenHashMaxLength,
            nameof(verificationCode));
        this.ExpiresAtUtc = expiresAtUtc > occurredAtUtc
            ? expiresAtUtc
            : throw new ArgumentOutOfRangeException(nameof(expiresAtUtc));
    }

    public MemberId MemberId { get; }
    public string Email { get; }
    public string VerificationCode { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
}
