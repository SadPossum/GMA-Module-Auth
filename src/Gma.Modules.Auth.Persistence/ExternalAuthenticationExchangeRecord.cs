namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Domain;

internal sealed class ExternalAuthenticationExchangeRecord : IScopedEntity
{
    public Guid Id { get; set; }
    public string ScopeId { get; set; } = string.Empty;
    public string CodeHash { get; set; } = string.Empty;
    public int Intent { get; set; }
    public string ProviderCode { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public Guid? TargetMemberId { get; set; }
    public Guid? TargetSessionId { get; set; }
    public string ReturnUrl { get; set; } = string.Empty;
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset? ConsumedAtUtc { get; set; }
}
