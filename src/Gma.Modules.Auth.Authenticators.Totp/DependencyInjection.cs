namespace Gma.Modules.Auth.Authenticators.Totp;

using Gma.Modules.Auth.Application.Ports;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

public static class DependencyInjection
{
    public static IHostApplicationBuilder AddAuthTotpAuthenticator(this IHostApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<AuthTotpOptions>()
            .Bind(builder.Configuration.GetSection(AuthTotpOptions.SectionName))
            .ValidateOnStart();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<Microsoft.Extensions.Options.IValidateOptions<AuthTotpOptions>, AuthTotpOptionsValidator>());
        builder.Services.AddDataProtection();
        builder.Services.Replace(
            ServiceDescriptor.Singleton<ITimeBasedOneTimePasswordProvider, TotpAuthenticatorProvider>());
        builder.Services.Replace(
            ServiceDescriptor.Singleton<IAuthenticatorSecretProtector, DataProtectionAuthenticatorSecretProtector>());

        return builder;
    }
}
