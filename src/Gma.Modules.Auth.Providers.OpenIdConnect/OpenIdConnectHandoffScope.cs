namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using Gma.Framework.Naming;
using Gma.Framework.Scoping;
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
        IScopeContextAccessor scopeContext = services.GetRequiredService<IScopeContextAccessor>();
        if (!scopeContext.IsEnabled)
        {
            return true;
        }

        if (properties?.Items.TryGetValue(OpenIdConnectHandoffProperties.ScopeId, out string? scopeId) != true ||
            !ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return false;
        }

        scopeContext.SetScope(normalizedScopeId);
        return string.Equals(scopeContext.ScopeId, normalizedScopeId, StringComparison.Ordinal);
    }
}
