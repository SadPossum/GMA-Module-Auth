namespace Gma.Modules.Auth.Contracts;

using Gma.Framework.Messaging;

public static class AuthIntegrationSubjects
{
    public static string MemberRegistered => CreateMemberRegistered();
    public static string MemberDisabled => CreateMemberDisabled();
    public static string MemberEnabled => CreateMemberEnabled();
    public static string MemberSessionsRevoked => CreateMemberSessionsRevoked();
    public static string MemberAuthenticated => CreateMemberAuthenticated();
    public static string MemberPasswordRecoveryRequested => CreateMemberPasswordRecoveryRequested();
    public static string MemberEmailVerificationRequested => CreateMemberEmailVerificationRequested();
    public static string MemberEmailVerified => CreateMemberEmailVerified();
    public static string MemberAuthenticationMethodChanged => CreateMemberAuthenticationMethodChanged();

    public static string CreateMemberRegistered(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberRegisteredIntegrationEvent.EventType, MemberRegisteredIntegrationEvent.EventVersion);

    public static string CreateMemberDisabled(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberDisabledIntegrationEvent.EventType, MemberDisabledIntegrationEvent.EventVersion);

    public static string CreateMemberEnabled(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberEnabledIntegrationEvent.EventType, MemberEnabledIntegrationEvent.EventVersion);

    public static string CreateMemberSessionsRevoked(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberSessionsRevokedIntegrationEvent.EventType, MemberSessionsRevokedIntegrationEvent.EventVersion);

    public static string CreateMemberAuthenticated(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberAuthenticatedIntegrationEvent.EventType, MemberAuthenticatedIntegrationEvent.EventVersion);

    public static string CreateMemberPasswordRecoveryRequested(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberPasswordRecoveryRequestedIntegrationEvent.EventType, MemberPasswordRecoveryRequestedIntegrationEvent.EventVersion);

    public static string CreateMemberEmailVerificationRequested(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberEmailVerificationRequestedIntegrationEvent.EventType, MemberEmailVerificationRequestedIntegrationEvent.EventVersion);

    public static string CreateMemberEmailVerified(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberEmailVerifiedIntegrationEvent.EventType, MemberEmailVerifiedIntegrationEvent.EventVersion);

    public static string CreateMemberAuthenticationMethodChanged(string subjectPrefix = IntegrationEventNaming.DefaultSubjectPrefix) =>
        IntegrationEventNaming.CreateSubject(subjectPrefix, AuthModuleMetadata.Name, MemberAuthenticationMethodChangedIntegrationEvent.EventType, MemberAuthenticationMethodChangedIntegrationEvent.EventVersion);
}
