namespace Gma.Modules.Auth.Tests;

using Gma.Framework.Naming;
using Gma.Framework.Scoping;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Providers.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthOpenIdConnectProviderTests
{
    [Fact]
    public void Disabled_configuration_registers_a_stable_empty_provider_contract()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();

        builder.AddAuthOpenIdConnectProviders();

        using IHost host = builder.Build();
        Assert.Empty(host.Services.GetRequiredService<OpenIdConnectProviderRegistry>().ProviderCodes);
        Assert.Single(host.Services.GetServices<Auth.Api.IAuthEndpointContributor>());
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
    [InlineData("https://client-secret@accounts.example.com")]
    [InlineData("https://accounts.example.com?tenant=one")]
    [InlineData("https://accounts.example.com#issuer")]
    public void Enabled_configuration_rejects_ambiguous_authorities(string authority)
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["google"].Authority = authority;

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("Authority", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("profile roles")]
    [InlineData("profile\\roles")]
    [InlineData("profile\nroles")]
    public void Enabled_configuration_rejects_invalid_scope_tokens(string scope)
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["google"].Scopes = ["openid", "email", scope];

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("valid OAuth scope tokens", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Enabled_configuration_bounds_scope_count()
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.Providers["google"].Scopes =
        [
            "openid",
            "email",
            .. Enumerable.Range(0, AuthOpenIdConnectProviderOptions.ScopeLimit).Select(index => $"scope-{index}"),
        ];

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("valid OAuth scope tokens", result.FailureMessage, StringComparison.Ordinal);
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
    public void Return_url_policy_allows_only_explicit_callback_paths_with_runtime_queries()
    {
        AuthOpenIdConnectOptions options = CreateOptions();
        options.AllowedReturnUrls = ["/auth/callback", "https://app.example.com/auth/callback"];
        var policy = new ExternalReturnUrlPolicy(options);

        Assert.True(policy.TryValidate("/auth/callback", out _));
        Assert.True(policy.TryValidate("/auth/callback?intent=sign-in", out _));
        Assert.True(policy.TryValidate("https://app.example.com/auth/callback?intent=link", out _));
        Assert.False(policy.TryValidate("/other", out _));
        Assert.False(policy.TryValidate("https://app.example.com/other", out _));
        Assert.False(policy.TryValidate("//evil.example.com", out _));
        Assert.False(policy.TryValidate("https://evil.example.com/callback", out _));
        Assert.False(policy.TryValidate("javascript:alert(1)", out _));
    }

    [Theory]
    [InlineData("http://localhost:8080/auth/callback")]
    [InlineData("http://127.0.0.1:8080/auth/callback")]
    [InlineData("http://[::1]:8080/auth/callback")]
    public void Return_url_policy_allows_http_only_for_explicit_loopback_callbacks(string returnUrl)
    {
        AuthOpenIdConnectOptions options = CreateOptions();
        options.AllowedReturnUrls = [returnUrl];
        var policy = new ExternalReturnUrlPolicy(options);

        Assert.True(policy.TryValidate($"{returnUrl}?intent=sign-in", out _));
    }

    [Fact]
    public void Enabled_configuration_rejects_non_loopback_http_callback()
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.AllowedReturnUrls = ["http://app.example.com/auth/callback"];

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("AllowedReturnUrls", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://app.example.com/auth/callback?intent=link")]
    [InlineData("https://app.example.com/auth/callback#fragment")]
    [InlineData("/auth/callback?intent=link")]
    public void Enabled_configuration_rejects_ambiguous_callback_allowlist_entries(string returnUrl)
    {
        var validator = new AuthOpenIdConnectOptionsValidator();
        AuthOpenIdConnectOptions options = CreateOptions();
        options.AllowedReturnUrls = [returnUrl];

        ValidateOptionsResult result = validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains("AllowedReturnUrls", result.FailureMessage, StringComparison.Ordinal);
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
            ["Auth:OpenIdConnect:AllowedReturnUrls:0"] = "/auth/callback",
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
            ["Auth:OpenIdConnect:AllowedReturnUrls:0"] = "/auth/callback",
        });

        builder.AddAuthOpenIdConnectProviders();
        builder.AddAuthOpenIdConnectProviders();

        using IHost host = builder.Build();
        Assert.NotNull(host.Services.GetService<OpenIdConnectProviderRegistry>());
        Assert.Single(builder.Services, descriptor => descriptor.ServiceType == typeof(Auth.Api.IAuthEndpointContributor));
    }

    [Fact]
    public async Task Remote_callback_failures_are_non_cacheable()
    {
        OpenIdConnectEvents events = OpenIdConnectEventsFactory.Create(new AuthOpenIdConnectProviderOptions());
        var httpContext = new DefaultHttpContext();
        AuthenticationProperties properties = new();
        properties.Items[OpenIdConnectHandoffProperties.ReturnUrl] = "/auth/complete";
        var context = new RemoteFailureContext(
            httpContext,
            new AuthenticationScheme("test", "test", typeof(OpenIdConnectHandler)),
            new OpenIdConnectOptions(),
            new InvalidOperationException("test failure"))
        {
            Properties = properties,
        };

        await events.OnRemoteFailure(context);

        Assert.Equal("no-store", httpContext.Response.Headers.CacheControl);
        Assert.Equal("no-cache", httpContext.Response.Headers.Pragma);
        Assert.True(context.Result?.Handled);
    }

    [Fact]
    public void Handoff_restores_the_normalized_scope_from_protected_authentication_state()
    {
        AuthenticationProperties properties = new();
        OpenIdConnectHandoffScope.Store(properties, "tenant-a");
        var accessor = new TestScopeContextAccessor();
        using ServiceProvider services = new ServiceCollection()
            .AddSingleton<IAuthScopeContext>(accessor)
            .BuildServiceProvider();

        bool restored = OpenIdConnectHandoffScope.TryRestore(properties, services);

        Assert.True(restored);
        Assert.Equal("tenant-a", accessor.ScopeId);
    }

    [Fact]
    public void Handoff_rejects_missing_scope_state()
    {
        using ServiceProvider services = new ServiceCollection()
            .AddSingleton<IAuthScopeContext>(new TestScopeContextAccessor())
            .BuildServiceProvider();

        Assert.False(OpenIdConnectHandoffScope.TryRestore(new AuthenticationProperties(), services));
    }

    [Fact]
    public void Handoff_allows_global_profiles_without_scope_state()
    {
        AuthenticationProperties properties = new();
        OpenIdConnectHandoffScope.Store(properties, scopeId: null);
        using ServiceProvider services = new ServiceCollection()
            .AddSingleton<IAuthScopeContext>(new TestScopeContextAccessor(enabled: false))
            .BuildServiceProvider();

        Assert.True(OpenIdConnectHandoffScope.TryRestore(properties, services));
        Assert.DoesNotContain(OpenIdConnectHandoffProperties.ScopeId, properties.Items.Keys);
    }

    [Fact]
    public void Handoff_for_a_fixed_global_profile_accepts_only_its_global_scope()
    {
        var scopeContext = new FixedTestAuthScopeContext("identity");
        using ServiceProvider services = new ServiceCollection()
            .AddSingleton<IAuthScopeContext>(scopeContext)
            .BuildServiceProvider();
        AuthenticationProperties matching = new();
        OpenIdConnectHandoffScope.Store(matching, "identity");
        AuthenticationProperties mismatched = new();
        OpenIdConnectHandoffScope.Store(mismatched, "tenant-a");

        Assert.True(OpenIdConnectHandoffScope.TryRestore(matching, services));
        Assert.False(OpenIdConnectHandoffScope.TryRestore(mismatched, services));
        Assert.Equal("identity", scopeContext.ScopeId);
    }

    [Fact]
    public void Browser_challenge_handoff_is_http_only_bounded_and_consumed_by_the_browser()
    {
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero));
        var handoff = new ExternalAuthenticationChallengeHandoff(
            new EphemeralDataProtectionProvider(),
            clock);
        var issueContext = new DefaultHttpContext();
        issueContext.Request.Scheme = "https";
        Guid memberId = Guid.NewGuid();
        Guid sessionId = Guid.NewGuid();

        ExternalAuthenticationChallengeResponse response = handoff.Issue(
            issueContext,
            "GOOGLE",
            "https://app.example.com/auth/complete",
            "tenant-a",
            Application.ExternalAuthentication.ExternalAuthenticationIntent.Link,
            memberId,
            sessionId);

        string setCookie = Assert.Single(issueContext.Response.Headers.SetCookie)!;
        Assert.StartsWith(ExternalAuthenticationChallengeHandoff.StartPath, response.StartUrl, StringComparison.Ordinal);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("max-age=300", setCookie, StringComparison.OrdinalIgnoreCase);

        var consumeContext = new DefaultHttpContext();
        consumeContext.Request.Scheme = "https";
        consumeContext.Request.Headers.Cookie = setCookie.Split(';', 2)[0];
        string nonce = response.StartUrl[(response.StartUrl.LastIndexOf('/') + 1)..];

        Assert.True(handoff.TryConsume(consumeContext, nonce, out var payload));
        Assert.NotNull(payload);
        Assert.Equal("google", payload.ProviderKey);
        Assert.Equal("tenant-a", payload.ScopeId);
        Assert.Equal(memberId, payload.TargetMemberId);
        Assert.Equal(sessionId, payload.TargetSessionId);
        Assert.Contains("expires=", Assert.Single(consumeContext.Response.Headers.SetCookie)!,
            StringComparison.OrdinalIgnoreCase);

        var replayContext = new DefaultHttpContext();
        Assert.False(handoff.TryConsume(replayContext, nonce, out _));
    }

    [Fact]
    public void Browser_challenge_handoff_rejects_expired_state()
    {
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 7, 14, 12, 0, 0, TimeSpan.Zero));
        var handoff = new ExternalAuthenticationChallengeHandoff(
            new EphemeralDataProtectionProvider(),
            clock);
        var issueContext = new DefaultHttpContext();
        ExternalAuthenticationChallengeResponse response = handoff.Issue(
            issueContext,
            "google",
            "/auth/complete",
            "tenant-a",
            Application.ExternalAuthentication.ExternalAuthenticationIntent.SignIn,
            targetMemberId: null,
            targetSessionId: null);
        string setCookie = Assert.Single(issueContext.Response.Headers.SetCookie)!;
        string nonce = response.StartUrl[(response.StartUrl.LastIndexOf('/') + 1)..];
        clock.Advance(TimeSpan.FromMinutes(6));
        var consumeContext = new DefaultHttpContext();
        consumeContext.Request.Headers.Cookie = setCookie.Split(';', 2)[0];

        Assert.False(handoff.TryConsume(consumeContext, nonce, out _));
    }

    private static AuthOpenIdConnectOptions CreateOptions() =>
        new()
        {
            Enabled = true,
            AllowedReturnUrls = ["/auth/callback"],
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

    private sealed class TestScopeContextAccessor(bool enabled = true) : IAuthScopeContext
    {
        public bool IsEnabled => enabled;
        public string? ScopeId { get; private set; }

        public void SetScope(string scopeId) => this.ScopeId = scopeId;
        public void ClearScope() => this.ScopeId = null;

        public bool TryRestoreScope(string? scopeId)
        {
            if (!enabled)
            {
                return true;
            }

            if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
            {
                return false;
            }

            this.SetScope(normalizedScopeId);
            return string.Equals(this.ScopeId, normalizedScopeId, StringComparison.Ordinal);
        }
    }

    private sealed class FixedTestAuthScopeContext(string scopeId) : IAuthScopeContext
    {
        public bool IsEnabled => true;
        public string ScopeId { get; } = ScopeIds.Normalize(scopeId);

        public bool TryRestoreScope(string? scopeId) =>
            ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId) &&
            string.Equals(this.ScopeId, normalizedScopeId, StringComparison.Ordinal);
    }

    private sealed class TestTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => this.utcNow;

        public void Advance(TimeSpan duration) => this.utcNow = this.utcNow.Add(duration);
    }

}
