namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using Gma.Framework.Naming;
using Gma.Modules.Auth.Application.Ports;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

internal static class OpenIdConnectHandoffScope
{
    public static void Store(AuthenticationProperties properties, string? scopeId)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            properties.Items[OpenIdConnectHandoffProperties.ScopeId] = normalizedScopeId;
        }
        else
        {
            properties.Items.Remove(OpenIdConnectHandoffProperties.ScopeId);
        }
    }

    public static bool TryRestore(AuthenticationProperties? properties, IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        IAuthScopeContext scopeContext = services.GetRequiredService<IAuthScopeContext>();
        string? scopeId = properties?.Items.TryGetValue(OpenIdConnectHandoffProperties.ScopeId, out string? storedScopeId) == true
            ? storedScopeId
            : null;
        return scopeContext.TryRestoreScope(scopeId);
    }
}
