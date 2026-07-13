namespace Gma.Modules.Auth.Providers.OpenIdConnect;

using Gma.Modules.Auth.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

public static class DependencyInjection
{
    private const string TemporaryCookieScheme = "gma.auth.external";

    public static IHostApplicationBuilder AddAuthOpenIdConnectProviders(this IHostApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (builder.Services.Any(descriptor =>
                descriptor.ServiceType == typeof(AuthOpenIdConnectRegistrationMarker)))
        {
            return builder;
        }

        AuthOpenIdConnectOptions configured = builder.Configuration
            .GetSection(AuthOpenIdConnectOptions.SectionName)
            .Get<AuthOpenIdConnectOptions>() ?? new AuthOpenIdConnectOptions();
        Validate(configured);
        builder.Services.AddSingleton<AuthOpenIdConnectRegistrationMarker>();

        builder.Services
            .AddOptions<AuthOpenIdConnectOptions>()
            .Bind(builder.Configuration.GetSection(AuthOpenIdConnectOptions.SectionName))
            .ValidateOnStart();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AuthOpenIdConnectOptions>, AuthOpenIdConnectOptionsValidator>());

        if (!configured.Enabled)
        {
            return builder;
        }

        builder.Services.AddSingleton(configured);
        builder.Services.AddSingleton<OpenIdConnectProviderRegistry>();
        builder.Services.AddSingleton<ExternalReturnUrlPolicy>();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthEndpointContributor, OpenIdConnectAuthEndpointContributor>());

        AuthenticationBuilder authentication = builder.Services
            .AddAuthentication()
            .AddCookie(TemporaryCookieScheme, options =>
            {
                options.Cookie.Name = "__Host-gma.auth.external";
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
                options.Cookie.Path = "/";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
                options.SlidingExpiration = false;
            });

        foreach ((string providerKey, AuthOpenIdConnectProviderOptions provider) in configured.Providers
                     .Where(pair => pair.Value.Enabled))
        {
            string normalizedProvider = OpenIdConnectProviderRegistry.NormalizeProviderKey(providerKey);
            string scheme = "gma.auth.external." + normalizedProvider;
            authentication.AddOpenIdConnect(scheme, options =>
            {
                options.SignInScheme = TemporaryCookieScheme;
                options.Authority = provider.Authority.TrimEnd('/');
                options.ClientId = provider.ClientId;
                options.ClientSecret = provider.ClientSecret;
                options.CallbackPath = $"/api/auth/external/callback/{normalizedProvider}";
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.UsePkce = true;
                options.SaveTokens = false;
                options.GetClaimsFromUserInfoEndpoint = false;
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters.NameClaimType = "name";
                options.Scope.Clear();
                foreach (string scope in provider.Scopes
                             .Where(scope => !string.IsNullOrWhiteSpace(scope))
                             .Select(scope => scope.Trim())
                             .Distinct(StringComparer.Ordinal))
                {
                    options.Scope.Add(scope);
                }

                options.Events = OpenIdConnectEventsFactory.Create(provider);
            });
        }

        return builder;
    }

    private static void Validate(AuthOpenIdConnectOptions options)
    {
        ValidateOptionsResult result = new AuthOpenIdConnectOptionsValidator().Validate(name: null, options);
        if (result.Failed)
        {
            throw new OptionsValidationException(
                AuthOpenIdConnectOptions.SectionName,
                typeof(AuthOpenIdConnectOptions),
                result.Failures);
        }
    }

    private sealed class AuthOpenIdConnectRegistrationMarker;
}
