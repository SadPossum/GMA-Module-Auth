namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

[IntegrationEventName(EventType)]
[IntegrationEventVersion(EventVersion)]
[ScopeAware]
public sealed record MemberAuthenticatedIntegrationEvent : IntegrationEvent, IScopedIntegrationEvent
{
    public const string EventType = "member-authenticated";
    public const int EventVersion = 1;

    public MemberAuthenticatedIntegrationEvent(
        Guid eventId,
        string scopeId,
        DateTimeOffset occurredAtUtc,
        Guid memberId,
        Guid sessionId,
        string authenticationMethod,
        string? ipAddress = null,
        string? userAgent = null)
        : base(eventId, occurredAtUtc, EventType, EventVersion)
    {
        this.ScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        this.MemberId = IntegrationEventContractGuards.RequireId(memberId, nameof(memberId));
        this.SessionId = IntegrationEventContractGuards.RequireId(sessionId, nameof(sessionId));
        this.AuthenticationMethod = IntegrationEventContractGuards.NormalizeRequiredText(
            authenticationMethod,
            AuthContractLimits.AuthenticationMethodMaxLength,
            nameof(authenticationMethod));
        this.IpAddress = NormalizeOptional(ipAddress, AuthContractLimits.IpAddressMaxLength, nameof(ipAddress));
        this.UserAgent = NormalizeOptional(userAgent, AuthContractLimits.UserAgentMaxLength, nameof(userAgent));
    }

    public string ScopeId { get; }
    public Guid MemberId { get; }
    public Guid SessionId { get; }
    public string AuthenticationMethod { get; }
    public string? IpAddress { get; }
    public string? UserAgent { get; }
    string IScopedIntegrationEvent.ScopeId => this.ScopeId;

    private static string? NormalizeOptional(string? value, int maximumLength, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = value.Trim();
        return normalized.Length <= maximumLength && !normalized.Any(char.IsControl)
            ? normalized
            : throw new ArgumentException(
                $"{parameterName} must be {maximumLength} characters or fewer and cannot contain control characters.",
                parameterName);
    }
}
