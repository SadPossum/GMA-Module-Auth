namespace Gma.Modules.Auth.Application.Ports;

using Gma.Framework.Scoping;

public interface IAuthScopeContext : IScopeContext
{
    bool TryRestoreScope(string? scopeId);
}
