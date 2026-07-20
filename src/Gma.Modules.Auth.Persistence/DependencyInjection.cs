namespace Gma.Modules.Auth.Persistence;

using Gma.Framework.Cqrs.UnitOfWork;
using Gma.Framework.Cqrs;
using Gma.Framework.Cqrs.Infrastructure;
using Gma.Framework.Messaging;
using Gma.Framework.Persistence.EntityFrameworkCore;
using Gma.Modules.Auth.Application;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Application.Scoping;
using Gma.Modules.Auth.Application.Security;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public static class DependencyInjection
{
    public static IHostApplicationBuilder AddAuthPersistence(this IHostApplicationBuilder builder)
        => builder.AddAuthPersistence(AuthProfile.ScopeAware());

    public static IHostApplicationBuilder AddAuthPersistence(
        this IHostApplicationBuilder builder,
        AuthProfile profile)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(profile);

        builder.Services.AddAuthScopeContext(profile);
        builder.Services.AddPersistenceOptions(builder.Configuration);
        AuthRetentionOptions retentionOptions = builder.Configuration
            .GetSection(AuthRetentionOptions.SectionName)
            .Get<AuthRetentionOptions>() ?? new();
        ValidateOptionsResult retentionValidation = new AuthRetentionOptionsValidator()
            .Validate(name: null, retentionOptions);
        if (retentionValidation.Failed)
        {
            throw new OptionsValidationException(
                AuthRetentionOptions.SectionName,
                typeof(AuthRetentionOptions),
                retentionValidation.Failures);
        }

        AuthApplicationOptions applicationOptions = builder.Configuration
            .GetSection(AuthApplicationOptions.SectionName)
            .Get<AuthApplicationOptions>() ?? new();
        ValidateOptionsResult compatibilityValidation = AuthRetentionOptionsValidator.ValidateCompatibility(
            retentionOptions,
            applicationOptions);
        if (compatibilityValidation.Failed)
        {
            throw new OptionsValidationException(
                AuthRetentionOptions.SectionName,
                typeof(AuthRetentionOptions),
                compatibilityValidation.Failures);
        }

        builder.Services
            .AddOptions<AuthRetentionOptions>()
            .Bind(builder.Configuration.GetSection(AuthRetentionOptions.SectionName))
            .ValidateOnStart();
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<AuthRetentionOptions>, AuthRetentionOptionsValidator>());

        builder.Services.TryAddModuleDbContext<AuthDbContext>(options =>
            options.UseConfiguredProvider(
                builder.Configuration,
                AuthMigrations.SqlServerAssembly,
                AuthMigrations.PostgreSqlAssembly,
                AuthMigrations.Schema,
                AuthMigrations.HistoryTable));

        builder.Services.TryAddScoped<IMemberRepository, MemberRepository>();
        builder.Services.TryAddScoped<IAdminMemberReadRepository, AdminMemberReadRepository>();
        builder.Services.TryAddScoped<IAuthMemberContactReader, AuthMemberContactReader>();
        builder.Services.TryAddScoped<IExternalAuthenticationExchangeStore, ExternalAuthenticationExchangeStore>();
        builder.Services.TryAddScoped<IPasswordRecoveryRecipientReader, PasswordRecoveryRecipientReader>();
        builder.Services.TryAddScoped<IPasswordRecoveryChallengeRepository, PasswordRecoveryChallengeRepository>();
        builder.Services.TryAddScoped<IPasswordRecoveryRequestSerializer, PasswordRecoveryRequestSerializer>();
        builder.Services.TryAddScoped<IAuthenticationChallengeRequestSerializer, AuthenticationChallengeRequestSerializer>();
        builder.Services.TryAddScoped<IMemberTotpAuthenticatorRepository, MemberTotpAuthenticatorRepository>();
        builder.Services.TryAddScoped<IMemberAuthenticationChallengeRepository, MemberAuthenticationChallengeRepository>();
        builder.Services.TryAddScoped<IMemberMultiFactorFailureAttemptRepository, MemberMultiFactorFailureAttemptRepository>();
        ServiceDescriptor[] processLocalLimiters = [.. builder.Services.Where(descriptor =>
            descriptor.ServiceType == typeof(IAuthenticationAttemptLimiter) &&
            descriptor.ImplementationType == typeof(ProcessLocalAuthenticationAttemptLimiter))];
        foreach (ServiceDescriptor processLocalLimiter in processLocalLimiters)
        {
            builder.Services.Remove(processLocalLimiter);
        }

        builder.Services.TryAddScoped<IAuthenticationAttemptLimiter, PersistentAuthenticationAttemptLimiter>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped(
            typeof(ICommandPipelineBehavior<,>),
            typeof(AuthPersistenceRetryBehavior<,>)));
        builder.Services.TryAddEnumerable([
            ServiceDescriptor.Scoped<IUnitOfWork, AuthUnitOfWork>(),
            ServiceDescriptor.Scoped<IOutboxWriter, AuthOutboxWriter>(),
            ServiceDescriptor.Scoped<IOutboxStore, AuthOutboxStore>()
        ]);
        builder.Services.MoveCommandUnitOfWorkBehaviorToEnd();
        if (retentionOptions.Enabled)
        {
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IHostedService, AuthRetentionService>());
        }

        return builder;
    }
}
