namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Permissions;
using Gma.Framework.Messaging;
using Gma.Framework.ModuleComposition;
using Gma.Framework.Modules;

public static class AuthModuleMetadata
{
    public const string Name = "auth";
    public const string Schema = "auth";

    public static ModuleDescriptor Descriptor { get; } = ModuleDescriptor
        .Create(Name)
        .WithSchema(Schema)
        .WithProfiles([AuthProfile.Global().Descriptor, AuthProfile.ScopeAware().Descriptor])
        .WithPermissions([
            new ModulePermissionDescriptor(AuthAdminPermissionCodes.MembersRead, "Read Auth members.", scopeRequirement: PermissionScopeRequirement.Scoped),
            new ModulePermissionDescriptor(AuthAdminPermissionCodes.MembersCreate, "Create Auth members.", scopeRequirement: PermissionScopeRequirement.Scoped),
            new ModulePermissionDescriptor(AuthAdminPermissionCodes.MembersDisable, "Disable Auth members.", scopeRequirement: PermissionScopeRequirement.Scoped),
            new ModulePermissionDescriptor(AuthAdminPermissionCodes.MembersEnable, "Enable Auth members.", scopeRequirement: PermissionScopeRequirement.Scoped),
            new ModulePermissionDescriptor(AuthAdminPermissionCodes.MembersResetPassword, "Reset Auth member passwords.", scopeRequirement: PermissionScopeRequirement.Scoped),
            new ModulePermissionDescriptor(AuthAdminPermissionCodes.MembersRevokeSessions, "Revoke Auth member sessions.", scopeRequirement: PermissionScopeRequirement.Scoped),
        ])
        .WithPublishedEvent<MemberRegisteredIntegrationEvent>()
        .WithPublishedEvent<MemberDisabledIntegrationEvent>()
        .WithPublishedEvent<MemberEnabledIntegrationEvent>()
        .WithPublishedEvent<MemberSessionsRevokedIntegrationEvent>()
        .WithPublishedEvent<MemberAuthenticatedIntegrationEvent>()
        .WithPublishedEvent<MemberAuthenticationMethodChangedIntegrationEvent>()
        .WithPublishedEvent<MemberEmailVerificationRequestedIntegrationEvent>()
        .WithPublishedEvent<MemberEmailVerifiedIntegrationEvent>()
        .Build();
}
