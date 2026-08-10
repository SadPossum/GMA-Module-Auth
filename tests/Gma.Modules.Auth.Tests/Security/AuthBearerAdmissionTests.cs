namespace Gma.Modules.Auth.Tests;

using System.Security.Claims;
using Gma.Framework.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Infrastructure.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthBearerAdmissionTests
{
    private const string ScopeId = "tenant-a";
    private static readonly Guid MemberId = Guid.NewGuid();
    private static readonly Guid SessionId = Guid.NewGuid();

    [Fact]
    public async Task Active_session_mode_composes_existing_handler_and_admits_exact_active_session()
    {
        var reader = new StubSessionAdmissionReader(isActive: true);
        using ServiceProvider services = CreateServices(reader);
        JwtBearerOptions options = new();
        bool existingHandlerCalled = false;
        options.Events.OnTokenValidated = _ =>
        {
            existingHandlerCalled = true;
            return Task.CompletedTask;
        };
        CreatePostConfigure(services, AuthBearerAdmissionMode.ActiveSession)
            .PostConfigure(JwtBearerDefaults.AuthenticationScheme, options);
        TokenValidatedContext context = CreateContext(services, options, CreatePrincipal());

        await options.Events.OnTokenValidated(context);

        Assert.True(existingHandlerCalled);
        Assert.Null(context.Result);
        Assert.Equal(1, reader.CallCount);
        Assert.Equal((ScopeId, MemberId, SessionId), reader.LastRequest);
    }

    [Fact]
    public async Task Active_session_mode_rejects_inactive_and_malformed_principals_without_disclosing_state()
    {
        var reader = new StubSessionAdmissionReader(isActive: false);
        using ServiceProvider services = CreateServices(reader);
        JwtBearerOptions options = new();
        CreatePostConfigure(services, AuthBearerAdmissionMode.ActiveSession)
            .PostConfigure(JwtBearerDefaults.AuthenticationScheme, options);

        TokenValidatedContext inactive = CreateContext(services, options, CreatePrincipal());
        await options.Events.OnTokenValidated(inactive);

        TokenValidatedContext malformed = CreateContext(
            services,
            options,
            CreatePrincipal(sessionId: Guid.Empty));
        await options.Events.OnTokenValidated(malformed);

        Assert.NotNull(inactive.Result?.Failure);
        Assert.NotNull(malformed.Result?.Failure);
        Assert.Equal(inactive.Result?.Failure?.Message, malformed.Result?.Failure?.Message);
        Assert.Equal(1, reader.CallCount);
    }

    [Fact]
    public async Task Token_lifetime_mode_preserves_stateless_validation_and_existing_handler()
    {
        using ServiceProvider services = new ServiceCollection().BuildServiceProvider();
        JwtBearerOptions options = new();
        bool existingHandlerCalled = false;
        options.Events.OnTokenValidated = _ =>
        {
            existingHandlerCalled = true;
            return Task.CompletedTask;
        };
        CreatePostConfigure(services, AuthBearerAdmissionMode.TokenLifetime)
            .PostConfigure(JwtBearerDefaults.AuthenticationScheme, options);
        TokenValidatedContext context = CreateContext(services, options, CreatePrincipal());

        await options.Events.OnTokenValidated(context);

        Assert.True(existingHandlerCalled);
        Assert.Null(context.Result);
    }

    [Fact]
    public void Active_session_mode_fails_configuration_without_reader_or_with_events_type()
    {
        using ServiceProvider noReader = new ServiceCollection().BuildServiceProvider();
        JwtBearerOptions missingReaderOptions = new();

        Assert.Throws<OptionsValidationException>(() =>
            CreatePostConfigure(noReader, AuthBearerAdmissionMode.ActiveSession)
                .PostConfigure(JwtBearerDefaults.AuthenticationScheme, missingReaderOptions));

        using ServiceProvider services = CreateServices(new StubSessionAdmissionReader(isActive: true));
        JwtBearerOptions customEventsOptions = new()
        {
            EventsType = typeof(JwtBearerEvents)
        };
        Assert.Throws<OptionsValidationException>(() =>
            CreatePostConfigure(services, AuthBearerAdmissionMode.ActiveSession)
                .PostConfigure(JwtBearerDefaults.AuthenticationScheme, customEventsOptions));
    }

    [Fact]
    public void Options_validator_rejects_unknown_mode()
    {
        var validator = new AuthBearerAdmissionOptionsValidator();

        Assert.True(validator.Validate(null, new AuthBearerAdmissionOptions
        {
            Mode = AuthBearerAdmissionMode.ActiveSession
        }).Succeeded);
        Assert.False(validator.Validate(null, new AuthBearerAdmissionOptions
        {
            Mode = (AuthBearerAdmissionMode)99
        }).Succeeded);
    }

    private static AuthBearerAdmissionPostConfigureOptions CreatePostConfigure(
        ServiceProvider services,
        AuthBearerAdmissionMode mode) =>
        new(
            Options.Create(new AuthBearerAdmissionOptions { Mode = mode }),
            services.GetRequiredService<IServiceProviderIsService>());

    private static ServiceProvider CreateServices(IAuthSessionAdmissionReader reader) =>
        new ServiceCollection()
            .AddSingleton(reader)
            .AddSingleton<IAuthSessionAdmissionReader>(reader)
            .BuildServiceProvider();

    private static TokenValidatedContext CreateContext(
        IServiceProvider services,
        JwtBearerOptions options,
        ClaimsPrincipal principal)
    {
        DefaultHttpContext httpContext = new()
        {
            RequestServices = services
        };
        AuthenticationScheme scheme = new(
            JwtBearerDefaults.AuthenticationScheme,
            JwtBearerDefaults.AuthenticationScheme,
            typeof(JwtBearerHandler));
        return new TokenValidatedContext(httpContext, scheme, options)
        {
            Principal = principal
        };
    }

    private static ClaimsPrincipal CreatePrincipal(
        string scopeId = ScopeId,
        Guid? memberId = null,
        Guid? sessionId = null) =>
        new(new ClaimsIdentity(
        [
            new Claim(ApplicationClaimNames.ScopeId, scopeId),
            new Claim(ApplicationClaimNames.Subject, (memberId ?? MemberId).ToString()),
            new Claim(ApplicationClaimNames.SessionId, (sessionId ?? SessionId).ToString())
        ], JwtBearerDefaults.AuthenticationScheme));

    private sealed class StubSessionAdmissionReader(bool isActive) : IAuthSessionAdmissionReader
    {
        public int CallCount { get; private set; }
        public (string ScopeId, Guid MemberId, Guid SessionId)? LastRequest { get; private set; }

        public ValueTask<bool> IsActiveAsync(
            string scopeId,
            Guid memberId,
            Guid sessionId,
            CancellationToken cancellationToken = default)
        {
            this.CallCount++;
            this.LastRequest = (scopeId, memberId, sessionId);
            return ValueTask.FromResult(isActive);
        }
    }
}
