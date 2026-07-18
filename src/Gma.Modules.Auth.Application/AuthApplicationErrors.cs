namespace Gma.Modules.Auth.Application;

using Gma.Modules.Auth.Domain.Errors;
using Gma.Framework.Results;

public static class AuthApplicationErrors
{
    public static readonly Error TenantRequired = new("Auth.TenantRequired", "A scope id is required.");
    public static readonly Error SelfRegistrationDisabled = new(
        "Auth.SelfRegistrationDisabled",
        "Self-registration is not enabled for this scope.");
    public static readonly Error UsernameTypeInvalid = new("Auth.UsernameTypeInvalid", "Username type must be email or phone.");
    public static readonly Error TokenInvalid = new("Auth.TokenInvalid", "Access token is invalid.");
    public static readonly Error TenantMismatch = new("Auth.TenantMismatch", "Access token tenant does not match the active tenant.");
    public static readonly Error PasswordBlocked = new(
        "Auth.PasswordBlocked",
        "Choose a password that is not commonly used or known to be compromised.");
    public static readonly Error ExternalExchangeInvalid = new(
        "Auth.ExternalExchangeInvalid",
        "External authentication exchange is invalid, expired, or already used.");
    public static readonly Error ExternalVerifiedEmailRequired = new(
        "Auth.ExternalVerifiedEmailRequired",
        "A provider-verified email is required to create an account.");
    public static readonly Error ExternalAccountLinkRequired = new(
        "Auth.ExternalAccountLinkRequired",
        "An account already uses this email. Sign in and link the provider explicitly.");
    public static readonly Error ExternalLinkAuthorizationRequired = new(
        "Auth.ExternalLinkAuthorizationRequired",
        "The external identity link must be completed by the authenticated member who started it.");
    public static readonly Error FreshAuthenticationRequired = new(
        "Auth.FreshAuthenticationRequired",
        "Fresh authentication is required for this security-sensitive operation.");
    public static readonly Error AlternateAuthenticationRequired = new(
        "Auth.AlternateAuthenticationRequired",
        "Authenticate with a different linked method or confirm the account password before unlinking this identity.");
    public static readonly Error ExternalIdentityAlreadyLinked = AuthDomainErrors.ExternalIdentityAlreadyLinked;
    public static readonly Error ExternalIdentityNotFound = AuthDomainErrors.ExternalIdentityNotFound;
    public static readonly Error PasswordNotConfigured = AuthDomainErrors.PasswordNotConfigured;
    public static readonly Error AuthenticationMethodRequired = AuthDomainErrors.AuthenticationMethodRequired;
    public static readonly Error EmailUsernameNotFound = AuthDomainErrors.EmailUsernameNotFound;
    public static readonly Error EmailAlreadyVerified = AuthDomainErrors.EmailAlreadyVerified;
    public static readonly Error EmailVerificationInvalid = new(
        "Auth.EmailVerificationInvalid",
        "Email verification code is invalid or expired.");
    public static readonly Error EmailVerificationRequestTooSoon = new(
        "Auth.EmailVerificationRequestTooSoon",
        "Wait before requesting another email verification message.");
    public static readonly Error PasswordRecoveryInvalid = new(
        "Auth.PasswordRecoveryInvalid",
        "Password recovery challenge is invalid, expired, or already used.");
    public static readonly Error CredentialsNotValid = AuthDomainErrors.CredentialsNotValid;
    public static readonly Error UsernameAlreadyExists = AuthDomainErrors.UsernameAlreadyExists;
    public static readonly Error MemberNotFound = AuthDomainErrors.MemberNotFound;
    public static readonly Error SessionNotFound = AuthDomainErrors.SessionNotFound;
    public static readonly Error SessionInactive = AuthDomainErrors.SessionInactive;
    public static readonly Error RefreshTokenInvalid = AuthDomainErrors.RefreshTokenInvalid;
    public static readonly Error RefreshTokenExpired = AuthDomainErrors.RefreshTokenExpired;
    public static readonly Error RefreshTokenReused = AuthDomainErrors.RefreshTokenReused;
    public static readonly Error MemberStatusUnknown = AuthDomainErrors.MemberStatusUnknown;
    public static readonly Error MemberDisabled = AuthDomainErrors.MemberDisabled;
    public static readonly Error MemberAlreadyDisabled = AuthDomainErrors.MemberAlreadyDisabled;
    public static readonly Error MemberAlreadyActive = AuthDomainErrors.MemberAlreadyActive;
}
