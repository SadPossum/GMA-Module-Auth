namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberAuthenticationMethodChangedIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-authentication-method-changed";
    public const int EventVersion = 1;

    public MemberAuthenticationMethodChangedIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        string authenticationMethod,
        AuthenticationMethodChange change)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.AuthenticationMethod = IntegrationEventContractGuards.NormalizeRequiredText(
            authenticationMethod,
            AuthContractLimits.AuthenticationMethodMaxLength,
            nameof(authenticationMethod));
        this.Change = change is not AuthenticationMethodChange.Unknown && Enum.IsDefined(change)
            ? change
            : throw new ArgumentOutOfRangeException(nameof(change));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public string AuthenticationMethod { get; }
    public AuthenticationMethodChange Change { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
