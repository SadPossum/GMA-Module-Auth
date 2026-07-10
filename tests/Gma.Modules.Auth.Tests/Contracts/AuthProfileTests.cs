namespace Gma.Modules.Auth.Tests.Contracts;

using Gma.Modules.Auth.Api;
using Gma.Modules.Auth.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Gma.Framework.ModuleComposition;
using Gma.Framework.Scoping;
using Gma.Framework.Scoping.Infrastructure;
using Xunit;

[Trait("Category", "Unit")]
public sealed class AuthProfileTests
{
    [Fact]
    public void Global_profile_does_not_require_scope_context()
    {
        AuthProfile profile = AuthProfile.Global("global");

        ModuleCompositionValidationResult result = ModuleCompositionValidator.Validate(new ModuleCompositionSnapshot(
            selectedProfiles: [new SelectedModuleProfile(profile.Descriptor)]));

        Assert.True(result.IsValid);
        Assert.False(profile.RequiresScopeContext);
        Assert.Equal("global", profile.GlobalScopeId);
        Assert.Contains(profile.Descriptor.Provides, feature => feature.Id == AuthCompositionFeatures.GlobalScope);
    }

    [Fact]
    public void Global_profile_composes_without_tenancy_module_using_default_scope_context()
    {
        IHostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(CreateValidAuthConfiguration());

        builder.AddScopingInfrastructure();
        builder.AddAuthModule(AuthProfile.Global("global"));

        ModuleCompositionValidationResult result = builder.ValidateModuleComposition();

        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));

        using ServiceProvider provider = builder.Services.BuildServiceProvider();
        using IServiceScope scope = provider.CreateScope();

        SelectedModuleProfile selectedProfile = Assert.Single(scope.ServiceProvider.GetServices<SelectedModuleProfile>());
        ScopeOptions scopeOptions = scope.ServiceProvider.GetRequiredService<IOptions<ScopeOptions>>().Value;
        IScopeContext scopeContext = scope.ServiceProvider.GetRequiredService<IScopeContext>();

        Assert.Equal(AuthModuleMetadata.Name, selectedProfile.Profile.ModuleName);
        Assert.Equal(AuthProfile.GlobalProfileName, selectedProfile.Profile.ProfileName);
        Assert.False(scopeOptions.Enabled);
        Assert.Equal("global", scopeOptions.LocalDefaultScopeId);
        Assert.False(scopeContext.IsEnabled);
        Assert.Equal("global", scopeContext.ScopeId);
    }

    [Fact]
    public void Tenant_scoped_profile_requires_scope_context()
    {
        AuthProfile profile = AuthProfile.ScopeAware();

        ModuleCompositionValidationResult result = ModuleCompositionValidator.Validate(new ModuleCompositionSnapshot(
            selectedProfiles: [new SelectedModuleProfile(profile.Descriptor)]));

        Assert.False(result.IsValid);
        Assert.Contains("scoping.context", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Tenant_scoped_profile_is_satisfied_by_scoping_profile()
    {
        AuthProfile profile = AuthProfile.ScopeAware();

        ModuleCompositionValidationResult result = ModuleCompositionValidator.Validate(new ModuleCompositionSnapshot(
            selectedProfiles:
            [
                new SelectedModuleProfile(CreateScopeContextProfile()),
                new SelectedModuleProfile(profile.Descriptor)
            ]));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Scoping_profile_advertises_context_only()
    {
        ModuleProfileDescriptor profile = CreateScopeContextProfile();

        Assert.Contains(profile.Provides, feature => feature.Id == ScopeCompositionFeatures.Context);
        Assert.DoesNotContain(profile.Provides, feature => feature.Id.Value.Contains("header", StringComparison.Ordinal));
    }

    private static ModuleProfileDescriptor CreateScopeContextProfile() => new(
        "test-scoping",
        "default",
        provides:
        [
            ScopeCompositionFeatures.ContextProvided("test-scoping/default")
        ]);

    private static IEnumerable<KeyValuePair<string, string?>> CreateValidAuthConfiguration() =>
    [
        new("Auth:Jwt:SigningKey", "test-jwt-signing-key-000000000000000000000000"),
        new("Auth:RefreshTokens:Pepper", "test-refresh-token-pepper-000000000000000000000000"),
        new("Persistence:Provider", "SqlServer"),
        new("ConnectionStrings:SqlServer", "Server=(localdb)\\mssqllocaldb;Database=GmaAuthProfileTests;Trusted_Connection=True;")
    ];
}
