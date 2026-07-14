namespace Gma.Modules.Auth.Persistence;

using Gma.Modules.Auth.Application.Ports;

public sealed class DesignTimeAuthScopeContext : IAuthScopeContext
{
    public bool IsEnabled => false;
    public string? ScopeId => null;
    public bool TryRestoreScope(string? scopeId) => true;
}
