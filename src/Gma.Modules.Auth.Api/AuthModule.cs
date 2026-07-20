namespace Gma.Modules.Auth.Api;

using System.Security.Claims;
using Gma.Framework.Api.Modules;
using Gma.Framework.Api.Observability;
using Gma.Framework.Api.Results;
using Gma.Framework.Api.Scoping;
using Gma.Framework.Cqrs;
using Gma.Framework.ModuleComposition;
using Gma.Framework.Results;
using Gma.Framework.Security;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Queries;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Infrastructure;
using Gma.Modules.Auth.Infrastructure.JwtBearer;
using Gma.Modules.Auth.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed partial class AuthModule(AuthProfile profile) : IModule
{
    private const string BrowserAccessCookieName = "gma.auth.access";
    private const string BrowserRefreshCookieName = "gma.auth.refresh";
    private const string BrowserRefreshCookiePath = "/api/auth/browser";
    private readonly AuthProfile profile = profile ?? throw new ArgumentNullException(nameof(profile));

    public AuthModule()
        : this(AuthProfile.ScopeAware())
    {
    }

    public string Name => AuthModuleMetadata.Name;

    public void AddServices(IHostApplicationBuilder builder)
    {
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupFilter, AuthNoStoreStartupFilter>());
        AddProfileServices(builder, this.profile);
        builder.Services.AddAuthApplication(builder.Configuration, this.profile);
        builder.Services.AddAuthInfrastructure(builder.Configuration);
        builder
            .AddAuthJwtBearerAuthentication()
            .AddAuthPersistence(this.profile);
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints)
    {
        bool requireScope = this.profile.RequiresScopeContext;
        RouteGroupBuilder group = endpoints.MapGroup("/api/auth")
            .WithModuleName(this.Name)
            .WithTags("Auth");

        this.MapCoreEndpoints(group, requireScope);
        this.MapMultiFactorEndpoints(group, requireScope);

        this.MapBrowserEndpoints(group, requireScope);

        foreach (IAuthEndpointContributor contributor in endpoints.ServiceProvider.GetServices<IAuthEndpointContributor>())
        {
            contributor.MapEndpoints(group, this.profile);
        }
    }
}

public static class AuthModuleHostBuilderExtensions
{
    public static IHostApplicationBuilder AddAuthModule(this IHostApplicationBuilder builder, AuthProfile profile)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(profile);

        return builder.AddModule(new AuthModule(profile));
    }
}
