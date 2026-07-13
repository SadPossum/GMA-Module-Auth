namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberAuthenticatedDomainEvent : ScopedDomainEvent
{
    public MemberAuthenticatedDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        MemberSessionId sessionId,
        string scopeId,
        string authenticationMethod,
        string? ipAddress,
        string? userAgent)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        _ = DomainEventGuards.RequireId(sessionId.Value, nameof(sessionId));
        if (!MemberAuthenticationMethods.TryNormalize(authenticationMethod, out string normalizedMethod))
        {
            throw new ArgumentException("Authentication method is invalid.", nameof(authenticationMethod));
        }

        this.MemberId = memberId;
        this.SessionId = sessionId;
        this.AuthenticationMethod = normalizedMethod;
        this.IpAddress = ipAddress;
        this.UserAgent = userAgent;
    }

    public MemberId MemberId { get; }
    public MemberSessionId SessionId { get; }
    public string AuthenticationMethod { get; }
    public string? IpAddress { get; }
    public string? UserAgent { get; }
}
