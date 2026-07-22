namespace Gma.Modules.Auth.Infrastructure;

using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static class TokenHashingDependencyInjection
{
    public static IServiceCollection AddAuthTokenHashingInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(AuthTokenHashingRegistrationMarker)))
        {
            return services;
        }

        ValidateOptions(configuration);
        services.AddSingleton<AuthTokenHashingRegistrationMarker>();
        services
            .AddOptions<RefreshTokenHashingOptions>()
            .Bind(configuration.GetSection(RefreshTokenHashingOptions.SectionName))
            .ValidateOnStart();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<RefreshTokenHashingOptions>, RefreshTokenHashingOptionsValidator>());
        services.TryAddScoped<IRefreshTokenHashingService, RefreshTokenHashingService>();

        return services;
    }

    private static void ValidateOptions(IConfiguration configuration)
    {
        RefreshTokenHashingOptions options = configuration
            .GetSection(RefreshTokenHashingOptions.SectionName)
            .Get<RefreshTokenHashingOptions>() ?? new RefreshTokenHashingOptions();
        ValidateOptionsResult result = new RefreshTokenHashingOptionsValidator().Validate(name: null, options);

        if (result.Failed)
        {
            throw new OptionsValidationException(
                RefreshTokenHashingOptions.SectionName,
                typeof(RefreshTokenHashingOptions),
                result.Failures);
        }
    }

    private sealed class AuthTokenHashingRegistrationMarker;
}
