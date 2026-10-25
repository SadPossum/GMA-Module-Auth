namespace Gma.Modules.Auth.Tests.Persistence;

using Gma.Framework.Application.Events.Infrastructure;
using Gma.Framework.Cqrs;
using Gma.Framework.Cqrs.UnitOfWork;
using Gma.Framework.Messaging.Infrastructure;
using Gma.Framework.Runtime.Infrastructure;
using Gma.Framework.Scoping.Infrastructure;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Gma.Modules.Auth.Infrastructure;
using Gma.Modules.Auth.Persistence;
using Gma.Modules.Auth.Persistence.Remembered;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.EntityFrameworkCore;
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
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IRememberedBrowserService>());
        Assert.Null(scope.ServiceProvider.GetService<RememberedBrowserService>());
        Assert.Null(scope.ServiceProvider.GetService<IPasswordHashingService>());
        Assert.Null(scope.ServiceProvider.GetService<ITokenService>());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("false")]
    public async Task Disabled_browser_api_host_validates_and_resolves_its_commands(string? enabled)
    {
        HostApplicationBuilder builder = CreateBuilder();
        builder.Configuration["Auth:RememberedBrowser:Enabled"] = enabled;
        builder.Configuration["Auth:Jwt:SigningKey"] = "test-jwt-signing-key-000000000000000000000000";
        new Gma.Modules.Auth.Api.AuthModule(AuthProfile.Global("identity")).AddServices(builder);

        using ServiceProvider provider = builder.Services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
        using IServiceScope scope = provider.CreateScope();

        var handler = scope.ServiceProvider.GetRequiredService<ICommandHandler<RememberedBrowserCommand, RememberedBrowserCompletion>>();
        var result = await handler.HandleAsync(new(new(RememberedBrowserOperationKind.Device, Guid.NewGuid(), 0)), CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(RememberedBrowserOutcome.Unavailable, result.Value.Response.Outcome);
        Assert.Null(result.Value.RefreshToken);
        Assert.Null(result.Value.DeviceCredential);
        Assert.Null(result.Value.Response.AccessToken);
    }

    [Fact]
    public async Task Disabled_browser_reports_no_current_accounts_or_recoverable_operation()
    {
        HostApplicationBuilder builder = CreateBuilder();
        Gma.Modules.Auth.Infrastructure.TokenHashing.DependencyInjection.AddAuthTokenHashingInfrastructure(
            builder.Services, builder.Configuration);
        builder.AddAuthPersistence(AuthProfile.Global("identity"));
        using ServiceProvider provider = builder.Services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
        using IServiceScope scope = provider.CreateScope();
        var browser = scope.ServiceProvider.GetRequiredService<IRememberedBrowserService>();

        RememberedBrowserCurrentResponse current = await browser.CurrentAsync(CancellationToken.None);
        RememberedBrowserOperationResponse outcome = await browser.OutcomeAsync(Guid.NewGuid(), CancellationToken.None);

        Assert.Equal(RememberedBrowserState.Unavailable, current.State);
        Assert.Empty(current.Accounts);
        Assert.Null(current.Active);
        Assert.Equal(RememberedBrowserOutcome.Unavailable, outcome.Outcome);
        Assert.Null(outcome.AccessToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Disabled_browser_refresh_preserves_ordinary_sessions_and_rejects_bound_sessions(bool browserBound)
    {
        HostApplicationBuilder builder = CreateBuilder();
        builder.Configuration["Auth:Jwt:SigningKey"] = "test-jwt-signing-key-000000000000000000000000";
        new Gma.Modules.Auth.Api.AuthModule(AuthProfile.Global("identity")).AddServices(builder);
        var databaseOptions = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options;
        builder.Services.RemoveAll<AuthDbContext>();
        builder.Services.AddScoped(services => new AuthDbContext(databaseOptions, services.GetRequiredService<IAuthScopeContext>()));
        using ServiceProvider provider = builder.Services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
        using IServiceScope scope = provider.CreateScope();
        IServiceProvider services = scope.ServiceProvider;
        var tokens = services.GetRequiredService<ITokenService>();
        var hashes = services.GetRequiredService<IRefreshTokenHashingService>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Member member = Member.Create(new(Guid.NewGuid()), "identity", "refresh@example.test",
            Gma.Modules.Auth.Domain.Enums.MemberUsernameType.Email, "password-hash", new(Guid.NewGuid()), Guid.NewGuid(), now).Value;
        var session = member.StartSession(new(Guid.NewGuid()), hashes.HashRefreshToken("refresh-token"), now.AddHours(1), now).Value;
        if (browserBound)
        {
            session.BindRememberedBrowser(Guid.NewGuid(), Guid.NewGuid(), 1, member.SecurityEpoch);
        }

        var db = services.GetRequiredService<AuthDbContext>();
        db.Members.Add(member);
        await db.SaveChangesAsync();
        string originalHash = session.RefreshTokenHash;
        string accessToken = tokens.GenerateAccessToken(new(member.Id, member.ScopeId, session.Id, SessionAuthenticationEvidence.Password(now)));
        var handler = services.GetRequiredService<ICommandHandler<RefreshMemberSessionCommand, RefreshTokenBoundCompletion<AuthTokensResponse>>>();

        var result = await handler.HandleAsync(new(accessToken, "refresh-token"), CancellationToken.None);

        if (browserBound)
        {
            Assert.True(result.IsFailure);
            Assert.Equal(AuthApplicationErrors.TokenInvalid, result.Error);
            Assert.Equal(originalHash, session.RefreshTokenHash);
        }
        else
        {
            Assert.True(result.IsSuccess);
            Assert.NotEqual(originalHash, session.RefreshTokenHash);
        }
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

        using ServiceProvider provider = builder.Services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });
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
        builder.AddMessagingInfrastructure();
        return builder;
    }
}
