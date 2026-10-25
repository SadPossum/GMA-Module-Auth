namespace Gma.Modules.Auth.Tests.Persistence;

using Gma.Framework.Application.Events.Infrastructure;
using Gma.Framework.Cqrs.UnitOfWork;
using Gma.Framework.Runtime.Infrastructure;
using Gma.Framework.Scoping.Infrastructure;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Infrastructure;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthRememberedBrowserRegistrationTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("false")]
    public void Persistence_only_host_validates_without_optional_browser_credentials(string? enabled)
    {
        HostApplicationBuilder builder = CreateBuilder();
        builder.Configuration["Auth:RememberedBrowser:Enabled"] = enabled;
        Gma.Modules.Auth.Infrastructure.TokenHashing.DependencyInjection.AddAuthTokenHashingInfrastructure(
            builder.Services, builder.Configuration);
        builder.AddAuthPersistence(AuthProfile.Global("identity"));

        using ServiceProvider provider = builder.Services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
        using IServiceScope scope = provider.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<AuthDbContext>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IUnitOfWork>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IAuthRememberedSessionAdmissionReader>());
        Assert.Null(scope.ServiceProvider.GetService<IRememberedBrowserService>());
        Assert.Null(scope.ServiceProvider.GetService<RememberedBrowserService>());
        Assert.Null(scope.ServiceProvider.GetService<IPasswordHashingService>());
        Assert.Null(scope.ServiceProvider.GetService<ITokenService>());
    }

    [Fact]
    public void Enabled_browser_resolves_with_the_full_auth_infrastructure()
    {
        HostApplicationBuilder builder = CreateBuilder();
        builder.Configuration["Auth:RememberedBrowser:Enabled"] = "true";
        builder.Configuration["Auth:RememberedBrowser:RestoreEpoch"] = "1";
        builder.Configuration["Auth:RememberedBrowser:PepperVersion"] = "test";
        builder.Configuration["Auth:RememberedBrowser:Pepper"] = Convert.ToBase64String(new byte[32]);
        builder.Configuration["Auth:Jwt:SigningKey"] = "test-jwt-signing-key-000000000000000000000000";
        builder.Services.AddAuthApplication(builder.Configuration, AuthProfile.Global("identity"));
        builder.Services.AddAuthInfrastructure(builder.Configuration);
        builder.AddAuthPersistence(AuthProfile.Global("identity"));

        using ServiceProvider provider = builder.Services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using IServiceScope scope = provider.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IRememberedBrowserService>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IPasswordHashingService>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<ITokenService>());
    }

    [Fact]
    public void Enabled_browser_keeps_its_required_auth_dependencies()
    {
        HostApplicationBuilder builder = CreateBuilder();
        builder.Configuration["Auth:RememberedBrowser:Enabled"] = "true";
        builder.AddAuthPersistence(AuthProfile.Global("identity"));

        Assert.Contains(builder.Services, descriptor => descriptor.ServiceType == typeof(RememberedBrowserService));
        Assert.Contains(builder.Services, descriptor => descriptor.ServiceType == typeof(IRememberedBrowserService));
        AggregateException error = Assert.Throws<AggregateException>(() => builder.Services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }));
        Assert.Contains(nameof(IPasswordHashingService), error.ToString(), StringComparison.Ordinal);
    }

    private static HostApplicationBuilder CreateBuilder()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            EnvironmentName = "Unit"
        });
        builder.Configuration["Auth:RefreshTokens:Pepper"] = "test-refresh-token-pepper-000000000000000000000000";
        builder.Configuration["ConnectionStrings:PostgreSql"] = "Host=localhost;Database=registration_test;Username=test;Password=test";
        builder.Configuration["Persistence:Provider"] = "PostgreSql";
        builder.AddRuntimeInfrastructure();
        builder.AddScopingInfrastructure();
        builder.AddApplicationEventsInfrastructure();
        return builder;
    }
}
