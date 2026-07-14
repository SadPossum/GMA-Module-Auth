namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.ModuleComposition;
using Gma.Framework.Naming;
using Gma.Framework.Scoping;

public sealed record AuthProfile
{
    public const string GlobalProfileName = "global";
    public const string ScopeAwareProfileName = "scope-aware";
    public const string DefaultGlobalScopeId = "global";

    private AuthProfile(
        string name,
        string? globalScopeId,
        bool requiresScopeContext,
        ModuleProfileDescriptor descriptor)
    {
        this.Name = name;
        this.GlobalScopeId = globalScopeId;
        this.RequiresScopeContext = requiresScopeContext;
        this.Descriptor = descriptor;
    }

    public string Name { get; }
    public string? GlobalScopeId { get; }
    public bool RequiresScopeContext { get; }
    public ModuleProfileDescriptor Descriptor { get; }

    public static AuthProfile Global(string scopeId = DefaultGlobalScopeId)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId);
        string provider = Provider(GlobalProfileName);
        return new AuthProfile(
            GlobalProfileName,
            normalizedScopeId,
            requiresScopeContext: false,
            new ModuleProfileDescriptor(
                AuthModuleMetadata.Name,
                GlobalProfileName,
                provides:
                [
                    AuthCompositionFeatures.MembersProvided(provider),
                    AuthCompositionFeatures.SessionsProvided(provider),
                    AuthCompositionFeatures.GlobalScopeProvided(provider)
                ],
                displayName: "Auth global",
                description: $"Stores all Auth members in the fixed '{normalizedScopeId}' scope independently of any ambient host scope."));
    }

    public static AuthProfile ScopeAware()
    {
        string provider = Provider(ScopeAwareProfileName);
        return new AuthProfile(
            ScopeAwareProfileName,
            globalScopeId: null,
            requiresScopeContext: true,
            new ModuleProfileDescriptor(
                AuthModuleMetadata.Name,
                ScopeAwareProfileName,
                provides:
                [
                    AuthCompositionFeatures.MembersProvided(provider),
                    AuthCompositionFeatures.SessionsProvided(provider),
                    AuthCompositionFeatures.ScopeContextProvided(provider)
                ],
                requires:
                [
                    new RequiredCompositionFeature(
                        ScopeCompositionFeatures.Context,
                        provider,
                        reason: "Register scoping infrastructure plus a scope provider, or choose AuthProfile.Global(\"global\") for a fixed identity scope.")
                ],
                displayName: "Auth scope-aware",
                description: "Stores Auth members in the resolved scope context and requires scope context."));
    }

    private static string Provider(string profileName) => $"{AuthModuleMetadata.Name}/{profileName}";
}
