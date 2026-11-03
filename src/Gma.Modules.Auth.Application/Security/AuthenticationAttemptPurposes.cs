namespace Gma.Modules.Auth.Application.Security;

public static class AuthenticationAttemptPurposes
{
    public const int MaxLength = 64;
    public const string PasswordLogin = "password-login";
    public const string PasswordStepUp = "password-step-up";
    public const string PasswordChange = "password-change";
    public const string PasswordRemoval = "password-removal";
    public const string ExternalIdentityUnlink = "external-identity-unlink";
    public const string MultiFactorManagement = "multi-factor-management";
    public const string MultiFactorStepUp = "multi-factor-step-up";
}
