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
        properties.Items[OpenIdConnectHandoffProperties.ScopeId] = ScopeIds.Normalize(scopeId!);
    }

    public static bool TryRestore(AuthenticationProperties? properties, IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (properties?.Items.TryGetValue(OpenIdConnectHandoffProperties.ScopeId, out string? scopeId) != true ||
            !ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return false;
        }

        IScopeContextAccessor scopeContext = services.GetRequiredService<IScopeContextAccessor>();
        scopeContext.SetScope(normalizedScopeId);
        return string.Equals(scopeContext.ScopeId, normalizedScopeId, StringComparison.Ordinal);
    }
}
