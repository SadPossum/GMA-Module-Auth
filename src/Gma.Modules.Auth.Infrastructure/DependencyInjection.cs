namespace Gma.Modules.Auth.Infrastructure;

using Gma.Framework.Runtime;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthTokenHashingInfrastructure(
        IServiceCollection services,
        IConfiguration configuration) =>
        TokenHashingDependencyInjection.AddAuthTokenHashingInfrastructure(services, configuration);

    public static IServiceCollection AddAuthInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(AuthInfrastructureRegistrationMarker)))
        {
            return services;
        }

        AuthInfrastructureOptionsValidation.Validate(configuration);
        services.AddAuthTokenHashingInfrastructure(configuration);
        ApplicationIdentityOptions applicationIdentity = configuration
            .GetSection(ApplicationIdentityOptions.SectionName)
            .Get<ApplicationIdentityOptions>() ?? new ApplicationIdentityOptions();
        services.AddSingleton<AuthInfrastructureRegistrationMarker>();
        services
            .AddOptions<JwtSettings>()
            .Bind(configuration.GetSection(JwtSettings.SectionName))
            .PostConfigure(options => AuthInfrastructureOptionsValidation.ApplyJwtIdentityDefaults(options, applicationIdentity))
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<JwtSettings>, JwtSettingsValidator>());
        services.TryAddScoped<IPasswordHashingService, PasswordHashingService>();
        services.TryAddScoped<IAuthOneTimeTokenService, AuthOneTimeTokenService>();
        services.TryAddScoped<IPasswordRecoveryTokenService, PasswordRecoveryTokenService>();
        services.TryAddScoped<ITokenService, JwtTokenService>();
        services.TryAddScoped<IMultiFactorTokenService, MultiFactorTokenService>();

        return services;
    }

    private sealed class AuthInfrastructureRegistrationMarker;
}
