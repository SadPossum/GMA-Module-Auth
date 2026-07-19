namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Domain;

internal sealed class AuthenticationAttemptRecord : IScopedEntity
{
    public const int PurposeMaxLength = 64;
    public const int TargetHashMaxLength = 512;

    public Guid Id { get; set; }
    public string ScopeId { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
    public string TargetHash { get; set; } = string.Empty;
    public DateTimeOffset FailedAtUtc { get; set; }
}
