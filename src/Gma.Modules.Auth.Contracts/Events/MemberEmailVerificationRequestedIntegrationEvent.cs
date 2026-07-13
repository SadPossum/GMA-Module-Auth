namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberEmailVerificationRequestedIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-email-verification-requested";
    public const int EventVersion = 1;

    public MemberEmailVerificationRequestedIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        string email,
        string verificationCode,
        DateTimeOffset expiresAtUtc)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.Email = IntegrationEventContractGuards.NormalizeRequiredText(
            email,
            AuthContractLimits.UsernameMaxLength,
            nameof(email));
        this.VerificationCode = IntegrationEventContractGuards.NormalizeRequiredText(
            verificationCode,
            AuthContractLimits.VerificationCodeMaxLength,
            nameof(verificationCode));
        this.ExpiresAtUtc = expiresAtUtc;
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public string Email { get; }
    public string VerificationCode { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
