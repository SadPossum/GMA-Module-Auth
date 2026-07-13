namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberAuthenticationMethodChangedDomainEvent : ScopedDomainEvent
{
    public MemberAuthenticationMethodChangedDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        string scopeId,
        string authenticationMethod,
        MemberAuthenticationMethodChange change)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        if (!MemberAuthenticationMethods.TryNormalize(authenticationMethod, out string normalizedMethod))
        {
            throw new ArgumentException("Authentication method is invalid.", nameof(authenticationMethod));
        }

        if (change is MemberAuthenticationMethodChange.Unknown || !Enum.IsDefined(change))
        {
            throw new ArgumentOutOfRangeException(nameof(change));
        }

        this.MemberId = memberId;
        this.AuthenticationMethod = normalizedMethod;
        this.Change = change;
    }

    public MemberId MemberId { get; }
    public string AuthenticationMethod { get; }
    public MemberAuthenticationMethodChange Change { get; }
}
