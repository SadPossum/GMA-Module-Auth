namespace Gma.Modules.Auth.Application.Scoping;

using Gma.Framework.Naming;
using Gma.Modules.Auth.Application.Ports;

internal sealed class FixedAuthScopeContext(string scopeId) : IAuthScopeContext
{
    public bool IsEnabled => true;
    public string ScopeId { get; } = ScopeIds.Normalize(scopeId);

    public bool TryRestoreScope(string? scopeId) =>
        ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) &&
        string.Equals(this.ScopeId, normalizedScopeId, StringComparison.Ordinal);
}
