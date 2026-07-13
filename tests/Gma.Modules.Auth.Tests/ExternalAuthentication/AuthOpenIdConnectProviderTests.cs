namespace Gma.Modules.Auth.Tests;

using Gma.Modules.Auth.Providers.OpenIdConnect;
using Gma.Framework.Scoping;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthOpenIdConnectProviderTests
{
    [Fact]
    public void Disabled_configuration_registers_without_provider_credentials()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();

        builder.AddAuthOpenIdConnectProviders();

        using IHost host = builder.Build();
        Assert.Null(host.Services.GetService<OpenIdConnectProviderRegistry>());
    }

    [Fact]
    public void Enabled_configuration_requires_https_authority_and_credentials()
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["google"].Authority = "http://accounts.google.com";

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("email\nclaim")]
    public void Enabled_configuration_rejects_invalid_claim_names(string claimName)
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["google"].EmailClaim = claimName;

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("claim names", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Enabled_configuration_rejects_provider_keys_that_normalize_to_the_same_scheme()
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers = new Dictionary<string, AuthOpenIdConnectProviderOptions>(StringComparer.Ordinal)
        {
            ["google"] = options.Providers["google"],
            [" Google "] = new()
            {
                Enabled = true,
                Authority = "https://accounts.google.com",
                ClientId = "other-client-id",
                ClientSecret = "other-client-secret",
            },
        };

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("duplicate normalized key 'google'", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Enabled_configuration_rejects_missing_provider_scopes_without_throwing()
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["google"].Scopes = null!;

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("Scopes configuration is required", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Return_url_policy_allows_local_paths_and_allowlisted_https_origins_only()
    {
        AuthOpenIdConnectOptions options = CreateOptions();
        options.AllowedReturnUrls = ["https://app.example.com/auth/callback"];
        var policy = new ExternalReturnUrlPolicy(options);

        Assert.True(policy.TryValidate("/auth/callback", out _));
        Assert.True(policy.TryValidate("https://app.example.com/other", out _));
        Assert.False(policy.TryValidate("//evil.example.com", out _));
        Assert.False(policy.TryValidate("https://evil.example.com/callback", out _));
        Assert.False(policy.TryValidate("javascript:alert(1)", out _));
    }

    [Fact]
    public void Provider_registry_normalizes_keys_and_exposes_enabled_providers_only()
    {
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["disabled"] = new AuthOpenIdConnectProviderOptions();
        var registry = new OpenIdConnectProviderRegistry(options);

        Assert.True(registry.TryGetScheme("GOOGLE", out string scheme));
        Assert.Equal("gma.auth.external.google", scheme);
        Assert.False(registry.TryGetScheme("disabled", out _));
    }

    [Fact]
    public void Registration_uses_code_pkce_and_does_not_save_provider_tokens()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:OpenIdConnect:Enabled"] = "true",
            ["Auth:OpenIdConnect:Providers:google:Enabled"] = "true",
            ["Auth:OpenIdConnect:Providers:google:Authority"] = "https://accounts.google.com",
            ["Auth:OpenIdConnect:Providers:google:ClientId"] = "client-id",
            ["Auth:OpenIdConnect:Providers:google:ClientSecret"] = "client-secret",
            ["Auth:OpenIdConnect:Providers:google:Scopes:0"] = "openid",
            ["Auth:OpenIdConnect:Providers:google:Scopes:1"] = "email",
        });
        builder.AddAuthOpenIdConnectProviders();

        using IHost host = builder.Build();
        OpenIdConnectOptions options = host.Services
            .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get("gma.auth.external.google");

        Assert.Equal("code", options.ResponseType);
        Assert.True(options.UsePkce);
        Assert.False(options.SaveTokens);
        Assert.False(options.GetClaimsFromUserInfoEndpoint);
        Assert.False(options.MapInboundClaims);
    }

    [Fact]
    public void Registration_is_repeat_safe()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:OpenIdConnect:Enabled"] = "true",
            ["Auth:OpenIdConnect:Providers:google:Enabled"] = "true",
            ["Auth:OpenIdConnect:Providers:google:Authority"] = "https://accounts.google.com",
            ["Auth:OpenIdConnect:Providers:google:ClientId"] = "client-id",
            ["Auth:OpenIdConnect:Providers:google:ClientSecret"] = "client-secret",
            ["Auth:OpenIdConnect:Providers:google:Scopes:0"] = "openid",
            ["Auth:OpenIdConnect:Providers:google:Scopes:1"] = "email",
        });

        builder.AddAuthOpenIdConnectProviders();
        builder.AddAuthOpenIdConnectProviders();

        using IHost host = builder.Build();
        Assert.NotNull(host.Services.GetService<OpenIdConnectProviderRegistry>());
        Assert.Single(builder.Services, descriptor => descriptor.ServiceType == typeof(Gma.Modules.Auth.Api.IAuthEndpointContributor));
    }

    [Fact]
    public void Handoff_restores_the_normalized_scope_from_protected_authentication_state()
    {
        AuthenticationProperties properties = new();
        OpenIdConnectHandoffScope.Store(properties, "tenant-a");
        var accessor = new TestScopeContextAccessor();
        using ServiceProvider services = new ServiceCollection()
            .AddSingleton<IScopeContextAccessor>(accessor)
            .BuildServiceProvider();

        bool restored = OpenIdConnectHandoffScope.TryRestore(properties, services);

        Assert.True(restored);
        Assert.Equal("tenant-a", accessor.ScopeId);
    }

    [Fact]
    public void Handoff_rejects_missing_scope_state()
    {
        using ServiceProvider services = new ServiceCollection()
            .AddSingleton<IScopeContextAccessor>(new TestScopeContextAccessor())
            .BuildServiceProvider();

        Assert.False(OpenIdConnectHandoffScope.TryRestore(new AuthenticationProperties(), services));
    }

    private static AuthOpenIdConnectOptions CreateOptions() =>
        new()
        {
            Enabled = true,
            Providers = new Dictionary<string, AuthOpenIdConnectProviderOptions>(StringComparer.OrdinalIgnoreCase)
            {
                ["google"] = new()
                {
                    Enabled = true,
                    Authority = "https://accounts.google.com",
                    ClientId = "client-id",
                    ClientSecret = "client-secret",
                },
            },
        };

    private sealed class TestScopeContextAccessor : IScopeContextAccessor
    {
        public bool IsEnabled => true;
        public string? ScopeId { get; private set; }

        public void SetScope(string scopeId) => this.ScopeId = scopeId;
        public void ClearScope() => this.ScopeId = null;
    }
}
