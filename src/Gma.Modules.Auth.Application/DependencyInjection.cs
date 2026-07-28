namespace Gma.Modules.Auth.Application;

using Gma.Framework.Application.Composition;
using Gma.Framework.Observability;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Scoping;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthApplication(this IServiceCollection services, IConfiguration configuration)
        => services.AddAuthApplication(configuration, AuthProfile.ScopeAware());

    public static IServiceCollection AddAuthApplication(
        this IServiceCollection services,
        IConfiguration configuration,
        AuthProfile profile)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(profile);

        if (!services.Any(descriptor => descriptor.ServiceType == typeof(AuthApplicationOptionsRegistrationMarker)))
        {
            AuthApplicationOptionsValidation.GetValidatedOptions(configuration);
            services.AddSingleton<AuthApplicationOptionsRegistrationMarker>();
            services
                .AddOptions<AuthApplicationOptions>()
                .Bind(configuration.GetSection(AuthApplicationOptions.SectionName))
                .ValidateOnStart();
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IValidateOptions<AuthApplicationOptions>, AuthApplicationOptionsValidator>());
        }

        services.AddAuthScopeContext(profile);
        services.AddSecuritySignalCore();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                ISecuritySignalDefinitionSource,
                AuthSecuritySignalDefinitions>());
        services.AddApplicationServicesFromAssembly(typeof(DependencyInjection).Assembly);
        services.TryAddSingleton<IPasswordBlocklist, CommonPasswordBlocklist>();
        services.TryAddSingleton<IAuthenticationAttemptLimiter, ProcessLocalAuthenticationAttemptLimiter>();
        services.TryAddScoped<PasswordProofService>();
        services.TryAddScoped<IExternalAuthenticationHandoffService, ExternalAuthenticationHandoffService>();
        services.TryAddSingleton<ITimeBasedOneTimePasswordProvider, UnavailableTimeBasedOneTimePasswordProvider>();
        services.TryAddSingleton<IAuthenticatorSecretProtector, UnavailableAuthenticatorSecretProtector>();
        services.TryAddScoped<MultiFactorAuthenticationService>();

        return services;
    }

    private sealed class AuthApplicationOptionsRegistrationMarker;
}
