namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberPasswordRecoveryRequestedIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-password-recovery-requested";
    public const int EventVersion = 1;

    public MemberPasswordRecoveryRequestedIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid challengeId,
        Guid memberId,
        string email,
        string recoveryCode,
        DateTimeOffset expiresAtUtc)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.ChallengeId = IntegrationEventContractGuards.RequireId(challengeId, nameof(challengeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.Email = IntegrationEventContractGuards.NormalizeRequiredText(
            email,
            AuthContractLimits.UsernameMaxLength,
            nameof(email));
        this.RecoveryCode = IntegrationEventContractGuards.NormalizeRequiredText(
            recoveryCode,
            AuthContractLimits.VerificationCodeMaxLength,
            nameof(recoveryCode));
        this.ExpiresAtUtc = expiresAtUtc > occurredAtUtc
            ? expiresAtUtc
            : throw new ArgumentOutOfRangeException(nameof(expiresAtUtc));
    }

    public string ScopeId { get; }
    public Guid ChallengeId { get; }
    public Guid MemberId { get; }
    public string Email { get; }
    public string RecoveryCode { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;
}
