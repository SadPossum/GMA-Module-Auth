namespace Gma.Modules.Auth.Application.Scoping;

using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class AuthScopeContextServiceCollectionExtensions
{
    public static IServiceCollection AddAuthScopeContext(
        this IServiceCollection services,
        AuthProfile profile)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(profile);

        AuthScopeProfileSelection requested = AuthScopeProfileSelection.From(profile);
        AuthScopeProfileSelection? selected = services
            .Where(descriptor => descriptor.ServiceType == typeof(AuthScopeProfileSelection))
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<AuthScopeProfileSelection>()
            .SingleOrDefault();

        if (selected is not null && selected != requested)
        {
            throw new InvalidOperationException(
                $"Auth scope profile '{requested.Name}' conflicts with already selected profile '{selected.Name}'.");
        }

        if (selected is null)
        {
            services.AddSingleton(requested);
        }

        services.TryAddScoped<IAuthScopeContext>(provider =>
        {
            AuthScopeProfileSelection selection = provider.GetRequiredService<AuthScopeProfileSelection>();
            return selection.RequiresAmbientScope
                ? new AmbientAuthScopeContext(provider.GetRequiredService<IScopeContextAccessor>())
                : new FixedAuthScopeContext(selection.FixedScopeId!);
        });

        return services;
    }

    private sealed record AuthScopeProfileSelection(
        string Name,
        bool RequiresAmbientScope,
        string? FixedScopeId)
    {
        public static AuthScopeProfileSelection From(AuthProfile profile) =>
            new(profile.Name, profile.RequiresScopeContext, profile.GlobalScopeId);
    }
}
