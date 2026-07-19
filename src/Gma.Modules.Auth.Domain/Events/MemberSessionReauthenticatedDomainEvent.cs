namespace Gma.Modules.Auth.Domain.Events;

using Gma.Framework.Domain;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed record MemberSessionReauthenticatedDomainEvent : ScopedDomainEvent
{
    public MemberSessionReauthenticatedDomainEvent(
        Guid eventId,
        DateTimeOffset occurredAtUtc,
        MemberId memberId,
        MemberSessionId sessionId,
        string scopeId,
        SessionAuthenticationEvidence authenticationEvidence)
        : base(eventId, occurredAtUtc, scopeId)
    {
        _ = DomainEventGuards.RequireId(memberId.Value, nameof(memberId));
        _ = DomainEventGuards.RequireId(sessionId.Value, nameof(sessionId));
        ArgumentNullException.ThrowIfNull(authenticationEvidence);

        this.MemberId = memberId;
        this.SessionId = sessionId;
        this.AuthenticationContextReference = authenticationEvidence.ContextReference;
        this.AuthenticationMethodReferences = authenticationEvidence.MethodReferences;
        this.AuthenticatedAtUtc = authenticationEvidence.AuthenticatedAtUtc;
    }

    public MemberId MemberId { get; }
    public MemberSessionId SessionId { get; }
    public string AuthenticationContextReference { get; }
    public IReadOnlyList<string> AuthenticationMethodReferences { get; }
    public DateTimeOffset AuthenticatedAtUtc { get; }
}
