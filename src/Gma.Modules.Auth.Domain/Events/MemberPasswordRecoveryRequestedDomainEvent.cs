namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberPasswordRecoveryRequestedDomainEvent : ScopedDomainEvent
{
    public MemberPasswordRecoveryRequestedDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        PasswordRecoveryChallengeId challengeId,
        MemberId memberId,
        string scopeId,
        string email,
        string recoveryCode,
        DateTimeOffset expiresAtUtc)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(challengeId.Value, nameof(challengeId));
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        this.ChallengeId = challengeId;
        this.MemberId = memberId;
        this.Email = DomainEventGuards.NormalizeRequiredText(email, MemberUsername.ValueMaxLength, nameof(email));
        this.RecoveryCode = DomainEventGuards.NormalizeRequiredText(
            recoveryCode,
            MemberSession.RefreshTokenHashMaxLength,
            nameof(recoveryCode));
        this.ExpiresAtUtc = expiresAtUtc > occurredAtUtc
            ? expiresAtUtc
            : throw new ArgumentOutOfRangeException(nameof(expiresAtUtc));
    }

    public PasswordRecoveryChallengeId ChallengeId { get; }
    public MemberId MemberId { get; }
    public string Email { get; }
    public string RecoveryCode { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
}
