namespace Gma.Modules.Auth.Application.Scoping;

using Gma.Framework.Naming;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;

internal sealed class AmbientAuthScopeContext(IScopeContextAccessor scopeContext) : IAuthScopeContext
{
    public bool IsEnabled => scopeContext.IsEnabled;
    public string? ScopeId => scopeContext.ScopeId;

    public bool TryRestoreScope(string? scopeId)
    {
        if (!scopeContext.IsEnabled)
        {
            return true;
        }

        if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return false;
        }

        scopeContext.SetScope(normalizedScopeId);
        return string.Equals(scopeContext.ScopeId, normalizedScopeId, StringComparison.Ordinal);
    }
}
