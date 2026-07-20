namespace Gma.Modules.Auth.Domain.Aggregates;

using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed partial class Member
{
    public Result ResetPassword(string passwordHash)
    {
        Result statusResult = this.EnsureKnownStatus();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (string.IsNullOrWhiteSpace(passwordHash) || passwordHash.Length > PasswordHashMaxLength)
        {
            return Result.Failure(AuthDomainErrors.PasswordNotValid);
        }

        this.PasswordHash = passwordHash.Trim();
        this.Touch();
        return Result.Success();
    }

    public Result RemovePassword()
    {
        Result statusResult = this.EnsureKnownStatus();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (this.PasswordHash is null)
        {
            return Result.Failure(AuthDomainErrors.PasswordNotConfigured);
        }

        if (this.externalIdentities.Count == 0)
        {
            return Result.Failure(AuthDomainErrors.AuthenticationMethodRequired);
        }

        this.PasswordHash = null;
        this.Touch();
        return Result.Success();
    }

    public Result<MemberExternalIdentity> LinkExternalIdentity(
        MemberExternalIdentityId identityId,
        string provider,
        string issuer,
        string subject,
        DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanAuthenticate();
        if (statusResult.IsFailure)
        {
            return Result.Failure<MemberExternalIdentity>(statusResult.Error);
        }

        Result<MemberExternalIdentity> identityResult = MemberExternalIdentity.Create(
            identityId,
            this.Id,
            this.ScopeId,
            provider,
            issuer,
            subject,
            nowUtc);
        if (identityResult.IsFailure)
        {
            return identityResult;
        }

        MemberExternalIdentity identity = identityResult.Value;
        if (this.externalIdentities.Any(item => item.Matches(identity.Issuer, identity.Subject)))
        {
            return Result.Failure<MemberExternalIdentity>(AuthDomainErrors.ExternalIdentityAlreadyLinked);
        }

        this.externalIdentities.Add(identity);
        this.Touch();
        return Result.Success(identity);
    }

    public Result UnlinkExternalIdentity(MemberExternalIdentityId identityId)
    {
        Result statusResult = this.EnsureKnownStatus();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        MemberExternalIdentity? identity = this.externalIdentities.FirstOrDefault(item => item.Id == identityId);
        if (identity is null)
        {
            return Result.Failure(AuthDomainErrors.ExternalIdentityNotFound);
        }

        if (this.PasswordHash is null && this.externalIdentities.Count == 1)
        {
            return Result.Failure(AuthDomainErrors.AuthenticationMethodRequired);
        }

        this.externalIdentities.Remove(identity);
        this.Touch();
        return Result.Success();
    }

    public Result MarkExternalIdentityAuthenticated(MemberExternalIdentityId identityId, DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanAuthenticate();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        MemberExternalIdentity? identity = this.externalIdentities.FirstOrDefault(item => item.Id == identityId);
        if (identity is null)
        {
            return Result.Failure(AuthDomainErrors.ExternalIdentityNotFound);
        }

        identity.MarkAuthenticated(nowUtc);
        this.Touch();
        return Result.Success();
    }

    public Result RequestEmailVerification(
        MemberUsernameId usernameId,
        string verificationTokenHash,
        string verificationCode,
        Guid requestedEventId,
        DateTimeOffset expiresAtUtc,
        DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanAuthenticate();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (requestedEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        if (string.IsNullOrWhiteSpace(verificationCode))
        {
            return Result.Failure(AuthDomainErrors.EmailVerificationTokenNotValid);
        }

        MemberUsername? username = this.usernames.FirstOrDefault(item => item.Id == usernameId && item.IsActive);
        if (username is null || username.UsernameType != MemberUsernameType.Email)
        {
            return Result.Failure(AuthDomainErrors.EmailUsernameNotFound);
        }

        Result result = username.RequestVerification(verificationTokenHash, expiresAtUtc, nowUtc);
        if (result.IsSuccess)
        {
            this.Touch();
            this.RaiseDomainEvent(new MemberEmailVerificationRequestedDomainEvent(
                requestedEventId,
                nowUtc,
                this.Id,
                this.ScopeId,
                username.Value,
                verificationCode,
                expiresAtUtc));
        }

        return result;
    }

    public Result ConfirmEmailVerification(
        MemberUsernameId usernameId,
        string verificationTokenHash,
        Guid verifiedEventId,
        DateTimeOffset nowUtc)
    {
        if (verifiedEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        MemberUsername? username = this.usernames.FirstOrDefault(item => item.Id == usernameId && item.IsActive);
        if (username is null || username.UsernameType != MemberUsernameType.Email)
        {
            return Result.Failure(AuthDomainErrors.EmailUsernameNotFound);
        }

        bool wasVerified = username.IsVerified;
        Result result = username.ConfirmVerification(verificationTokenHash, nowUtc);
        if (result.IsSuccess && !wasVerified)
        {
            this.Touch();
            this.RaiseDomainEvent(new MemberEmailVerifiedDomainEvent(
                verifiedEventId,
                nowUtc,
                this.Id,
                this.ScopeId,
                username.Value));
        }

        return result;
    }

    public Result RecordAuthentication(
        MemberSessionId sessionId,
        Guid authenticatedEventId,
        DateTimeOffset nowUtc,
        string? ipAddress = null,
        string? userAgent = null)
    {
        if (authenticatedEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        MemberSession? session = this.sessions.FirstOrDefault(item => item.Id == sessionId && item.IsActive);
        if (session is null)
        {
            return Result.Failure(AuthDomainErrors.SessionNotFound);
        }

        this.RaiseDomainEvent(new MemberAuthenticatedDomainEvent(
            authenticatedEventId,
            nowUtc,
            this.Id,
            session.Id,
            this.ScopeId,
            session.AuthenticationMethod,
            ipAddress,
            userAgent));
        return Result.Success();
    }

    public Result RecordAuthenticationMethodChanged(
        string authenticationMethod,
        MemberAuthenticationMethodChange change,
        Guid changedEventId,
        DateTimeOffset nowUtc)
    {
        if (changedEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        if (!MemberAuthenticationMethods.TryNormalize(authenticationMethod, out string normalizedMethod) ||
            change is MemberAuthenticationMethodChange.Unknown ||
            !Enum.IsDefined(change))
        {
            return Result.Failure(AuthDomainErrors.AuthenticationMethodNotValid);
        }

        this.RaiseDomainEvent(new MemberAuthenticationMethodChangedDomainEvent(
            changedEventId,
            nowUtc,
            this.Id,
            this.ScopeId,
            normalizedMethod,
            change));
        return Result.Success();
    }
}
