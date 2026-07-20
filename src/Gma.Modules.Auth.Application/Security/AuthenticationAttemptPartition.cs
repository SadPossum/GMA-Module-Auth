namespace Gma.Modules.Auth.Application.Security;

using Gma.Framework.Naming;

public sealed record AuthenticationAttemptPartition
{
    public const int TargetMaxLength = 512;

    private AuthenticationAttemptPartition(string scopeId, string purpose, string target)
    {
        this.ScopeId = scopeId;
        this.Purpose = purpose;
        this.Target = target;
    }

    public string ScopeId { get; }
    public string Purpose { get; }
    public string Target { get; }
    public string Key => $"{this.ScopeId}\n{this.Purpose}\n{this.Target}";

    public static AuthenticationAttemptPartition Create(string scopeId, string purpose, string target)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId);
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        string normalizedPurpose = purpose.Trim().ToLowerInvariant();
        if (normalizedPurpose.Length > AuthenticationAttemptPurposes.MaxLength || normalizedPurpose.Any(char.IsControl))
        {
            throw new ArgumentException("Authentication attempt purpose is invalid.", nameof(purpose));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        string normalizedTarget = target.Trim().ToUpperInvariant();
        if (normalizedTarget.Length > TargetMaxLength || normalizedTarget.Any(char.IsControl))
        {
            throw new ArgumentException("Authentication attempt target is invalid.", nameof(target));
        }

        return new AuthenticationAttemptPartition(normalizedScopeId, normalizedPurpose, normalizedTarget);
    }
}
