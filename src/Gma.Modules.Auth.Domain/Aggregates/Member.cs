namespace Gma.Modules.Auth.Domain.Aggregates;

using Gma.Framework.Domain.Models;
using Gma.Framework.Naming;
using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed class Member : ScopedAggregateRoot<MemberId>
{
    public const int PasswordHashMaxLength = 512;
    public const int DisabledReasonMaxLength = 512;

    private readonly List<MemberSession> sessions = [];
    private readonly List<MemberUsername> usernames = [];
    private readonly List<MemberExternalIdentity> externalIdentities = [];

    private Member() { }

    private Member(MemberId id, string scopeId, string? passwordHash)
        : base(id, scopeId)
    {
        this.PasswordHash = passwordHash;
        this.Status = MemberStatus.Active;
    }

    public string? PasswordHash { get; private set; }
    public bool HasPassword => this.PasswordHash is not null;
    public Guid ConcurrencyStamp { get; private set; }
    public MemberStatus Status { get; private set; } = MemberStatus.Active;
    public DateTimeOffset RegisteredAtUtc { get; private set; }
    public DateTimeOffset? DisabledAtUtc { get; private set; }
    public string? DisabledReason { get; private set; }
    public IReadOnlyCollection<MemberUsername> Usernames => this.usernames;
    public IReadOnlyCollection<MemberSession> Sessions => this.sessions;
    public IReadOnlyCollection<MemberExternalIdentity> ExternalIdentities => this.externalIdentities;

    public static Result<Member> Create(
        MemberId id,
        string scopeId,
        string username,
        MemberUsernameType usernameType,
        string passwordHash,
        MemberUsernameId usernameId,
        Guid registeredEventId,
        DateTimeOffset registeredAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.MemberIdRequired);
        }

        if (registeredEventId == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.DomainEventIdRequired);
        }

        if (string.IsNullOrWhiteSpace(scopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantInvalid);
        }

        if (string.IsNullOrWhiteSpace(passwordHash) || passwordHash.Length > PasswordHashMaxLength)
        {
            return Result.Failure<Member>(AuthDomainErrors.PasswordNotValid);
        }

        Member member = new(id, normalizedScopeId, passwordHash)
        {
            RegisteredAtUtc = registeredAtUtc,
            ConcurrencyStamp = Guid.CreateVersion7()
        };
        Result<MemberUsername> usernameResult = member.AddUsername(usernameId, username, usernameType);

        if (usernameResult.IsFailure)
        {
            return Result.Failure<Member>(usernameResult.Error);
        }

        member.RaiseDomainEvent(new MemberRegisteredDomainEvent(
            registeredEventId,
            registeredAtUtc,
            member.Id,
            member.ScopeId,
            usernameResult.Value.Value));

        return Result.Success(member);
    }

    public static Result<Member> CreateExternal(
        MemberId id,
        string scopeId,
        string verifiedEmail,
        MemberUsernameId usernameId,
        MemberExternalIdentityId externalIdentityId,
        string provider,
        string issuer,
        string subject,
        Guid registeredEventId,
        DateTimeOffset registeredAtUtc)
    {
        if (registeredEventId == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.DomainEventIdRequired);
        }

        Result<Member> memberResult = CreateCore(id, scopeId, null, registeredAtUtc);
        if (memberResult.IsFailure)
        {
            return memberResult;
        }

        Member member = memberResult.Value;
        Result<MemberUsername> usernameResult = member.AddUsername(
            usernameId,
            verifiedEmail,
            MemberUsernameType.Email,
            registeredAtUtc);
        if (usernameResult.IsFailure)
        {
            return Result.Failure<Member>(usernameResult.Error);
        }

        Result<MemberExternalIdentity> identityResult = member.LinkExternalIdentity(
            externalIdentityId,
            provider,
            issuer,
            subject,
            registeredAtUtc);
        if (identityResult.IsFailure)
        {
            return Result.Failure<Member>(identityResult.Error);
        }

        member.RaiseDomainEvent(new MemberRegisteredDomainEvent(
            registeredEventId,
            registeredAtUtc,
            member.Id,
            member.ScopeId,
            usernameResult.Value.Value));

        return Result.Success(member);
    }

    public Result<MemberUsername> AddUsername(
        MemberUsernameId usernameId,
        string value,
        MemberUsernameType usernameType,
        DateTimeOffset? verifiedAtUtc = null)
    {
        Result<MemberUsername> usernameResult = MemberUsername.Create(
            usernameId,
            this.Id,
            this.ScopeId,
            value,
            usernameType);

        if (usernameResult.IsFailure)
        {
            return Result.Failure<MemberUsername>(usernameResult.Error);
        }

        MemberUsername newUsername = usernameResult.Value;
        if (this.usernames.Any(username => username.NormalizedValue == newUsername.NormalizedValue))
        {
            return Result.Failure<MemberUsername>(AuthDomainErrors.UsernameAlreadyExists);
        }

        MemberUsername? current = this.usernames.FirstOrDefault(username =>
            username.UsernameType == usernameType && username.IsActive);

        current?.Deactivate();
        if (verifiedAtUtc is not null)
        {
            newUsername.MarkVerified(verifiedAtUtc.Value);
        }

        this.usernames.Add(newUsername);
        this.Touch();

        return Result.Success(newUsername);
    }

    public bool HasActiveUsername(string username) =>
        MemberUsername.TryNormalize(username, out string? normalizedUsername) &&
        this.usernames.Any(memberUsername =>
            memberUsername.IsActive &&
            memberUsername.NormalizedValue == normalizedUsername);

    public Result<MemberSession> StartSession(
        MemberSessionId sessionId,
        string refreshTokenHash,
        DateTimeOffset refreshTokenExpiresAtUtc,
        DateTimeOffset nowUtc,
        string authenticationMethod = MemberAuthenticationMethods.Password,
        SessionAuthenticationEvidence? authenticationEvidence = null,
        int maximumActiveSessions = int.MaxValue)
    {
        Result statusResult = this.EnsureCanAuthenticate();
        if (statusResult.IsFailure)
        {
            return Result.Failure<MemberSession>(statusResult.Error);
        }

        if (maximumActiveSessions < 1)
        {
            return Result.Failure<MemberSession>(AuthDomainErrors.SessionLimitInvalid);
        }

        Result<MemberSession> sessionResult = MemberSession.Create(
            sessionId,
            this.Id,
            this.ScopeId,
            refreshTokenHash,
            refreshTokenExpiresAtUtc,
            nowUtc,
            authenticationMethod,
            authenticationEvidence);

        if (sessionResult.IsFailure)
        {
            return Result.Failure<MemberSession>(sessionResult.Error);
        }

        MemberSession session = sessionResult.Value;
        this.sessions.Add(session);
        int excessSessionCount = Math.Max(
            0,
            this.sessions.Count(item => item.IsActive && item.RefreshTokenExpiresAtUtc > nowUtc) -
            maximumActiveSessions);
        MemberSession[] excessSessions = [.. this.sessions
            .Where(item =>
                item.Id != session.Id &&
                item.IsActive &&
                item.RefreshTokenExpiresAtUtc > nowUtc)
            .OrderBy(item => item.LoginDateTimeUtc)
            .ThenBy(item => item.Id.Value)
            .Take(excessSessionCount)];
        foreach (MemberSession excessSession in excessSessions)
        {
            _ = excessSession.SignOut(nowUtc);
        }

        this.Touch();

        return Result.Success(session);
    }

    public Result<MemberSession> RefreshSession(
        MemberSessionId sessionId,
        string refreshTokenHash,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        DateTimeOffset nowUtc) =>
        this.RefreshSession(
            sessionId,
            [refreshTokenHash],
            newRefreshTokenHash,
            newRefreshTokenExpiresAtUtc,
            nowUtc);

    public Result<MemberSession> RefreshSession(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        DateTimeOffset nowUtc)
    {
        Result<MemberSession> result = this.RotateSessionRefreshToken(
            sessionId,
            refreshTokenHashes,
            newRefreshTokenHash,
            newRefreshTokenExpiresAtUtc,
            nowUtc);
        if (result.IsSuccess)
        {
            this.Touch();
        }

        return result;
    }

    public Result<MemberSession> ReauthenticateSession(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        SessionAuthenticationEvidence authenticationEvidence,
        Guid reauthenticatedEventId,
        DateTimeOffset nowUtc)
    {
        if (reauthenticatedEventId == Guid.Empty)
        {
            return Result.Failure<MemberSession>(AuthDomainErrors.DomainEventIdRequired);
        }

        ArgumentNullException.ThrowIfNull(authenticationEvidence);
        Result<MemberSession> result = this.RotateSessionRefreshToken(
            sessionId,
            refreshTokenHashes,
            newRefreshTokenHash,
            newRefreshTokenExpiresAtUtc,
            nowUtc);
        if (result.IsFailure)
        {
            return result;
        }

        result.Value.RecordAuthenticationEvidence(authenticationEvidence);
        this.Touch();
        this.RaiseDomainEvent(new MemberSessionReauthenticatedDomainEvent(
            reauthenticatedEventId,
            nowUtc,
            this.Id,
            result.Value.Id,
            this.ScopeId,
            authenticationEvidence));
        return result;
    }

    private Result<MemberSession> RotateSessionRefreshToken(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanAuthenticate();
        if (statusResult.IsFailure)
        {
            return Result.Failure<MemberSession>(statusResult.Error);
        }

        ArgumentNullException.ThrowIfNull(refreshTokenHashes);
        MemberSession? reusedSession = this.sessions.FirstOrDefault(item =>
            item.Id == sessionId && refreshTokenHashes.Any(item.HasPreviousRefreshTokenHash));
        if (reusedSession is not null)
        {
            foreach (MemberSession activeSession in this.sessions.Where(item => item.IsActive))
            {
                activeSession.SignOut(nowUtc);
            }

            this.Touch();
            return Result.Failure<MemberSession>(AuthDomainErrors.RefreshTokenReused);
        }

        MemberSession? session = this.sessions.FirstOrDefault(item =>
            item.Id == sessionId && refreshTokenHashes.Any(item.HasRefreshTokenHash));
        if (session is null)
        {
            return Result.Failure<MemberSession>(AuthDomainErrors.SessionNotFound);
        }

        string matchingHash = refreshTokenHashes.First(session.HasRefreshTokenHash);
        Result result = session.Refresh(matchingHash, newRefreshTokenHash, newRefreshTokenExpiresAtUtc, nowUtc);
        return result.IsSuccess
            ? Result.Success(session)
            : Result.Failure<MemberSession>(result.Error);
    }

    public Result SignOut(string refreshTokenHash, DateTimeOffset nowUtc)
        => this.SignOut([refreshTokenHash], nowUtc);

    public Result SignOut(IReadOnlyCollection<string> refreshTokenHashes, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(refreshTokenHashes);
        MemberSession? session = this.sessions.FirstOrDefault(item => refreshTokenHashes.Any(item.HasRefreshTokenHash));

        if (session is null)
        {
            return Result.Failure(AuthDomainErrors.SessionNotFound);
        }

        Result result = session.SignOut(nowUtc);
        if (result.IsSuccess)
        {
            this.Touch();
        }

        return result;
    }

    public Result SignOutAll(DateTimeOffset nowUtc)
    {
        List<MemberSession> activeSessions = [.. this.sessions.Where(session => session.IsActive)];

        if (activeSessions.Count == 0)
        {
            return Result.Failure(AuthDomainErrors.SessionNotFound);
        }

        foreach (MemberSession session in activeSessions)
        {
            session.SignOut(nowUtc);
        }

        this.Touch();

        return Result.Success();
    }

    public Result SignOutSession(MemberSessionId sessionId, DateTimeOffset nowUtc)
    {
        MemberSession? session = this.sessions.FirstOrDefault(item => item.Id == sessionId);
        if (session is null)
        {
            return Result.Failure(AuthDomainErrors.SessionNotFound);
        }

        Result result = session.SignOut(nowUtc);
        if (result.IsSuccess)
        {
            this.Touch();
        }

        return result;
    }

    public Result Disable(string reason, Guid disabledEventId, DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanDisable();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (disabledEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            return Result.Failure(AuthDomainErrors.DisableReasonRequired);
        }

        string trimmedReason = reason.Trim();

        if (trimmedReason.Length > DisabledReasonMaxLength)
        {
            return Result.Failure(AuthDomainErrors.DisableReasonTooLong);
        }

        this.Status = MemberStatus.Disabled;
        this.DisabledAtUtc = nowUtc;
        this.DisabledReason = trimmedReason;
        this.Touch();

        foreach (MemberSession session in this.sessions.Where(session => session.IsActive))
        {
            session.SignOut(nowUtc);
        }

        this.RaiseDomainEvent(new MemberDisabledDomainEvent(
            disabledEventId,
            nowUtc,
            this.Id,
            this.ScopeId,
            trimmedReason));

        return Result.Success();
    }

    public Result Enable(Guid enabledEventId, DateTimeOffset nowUtc)
    {
        Result statusResult = this.EnsureCanEnable();
        if (statusResult.IsFailure)
        {
            return statusResult;
        }

        if (enabledEventId == Guid.Empty)
        {
            return Result.Failure(AuthDomainErrors.DomainEventIdRequired);
        }

        this.Status = MemberStatus.Active;
        this.DisabledAtUtc = null;
        this.DisabledReason = null;
        this.Touch();
        this.RaiseDomainEvent(new MemberEnabledDomainEvent(enabledEventId, nowUtc, this.Id, this.ScopeId));

        return Result.Success();
    }

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

    public Result<int> RevokeSessions(Guid revokedEventId, DateTimeOffset nowUtc)
    {
        if (revokedEventId == Guid.Empty)
        {
            return Result.Failure<int>(AuthDomainErrors.DomainEventIdRequired);
        }

        List<MemberSession> activeSessions = [.. this.sessions.Where(session => session.IsActive)];

        foreach (MemberSession session in activeSessions)
        {
            session.SignOut(nowUtc);
        }

        if (activeSessions.Count > 0)
        {
            this.Touch();
        }

        if (activeSessions.Count > 0)
        {
            this.RaiseDomainEvent(new MemberSessionsRevokedDomainEvent(
                revokedEventId,
                nowUtc,
                this.Id,
                this.ScopeId,
                activeSessions.Count));
        }

        return Result.Success(activeSessions.Count);
    }

    private Result EnsureCanAuthenticate() =>
        this.Status switch
        {
            MemberStatus.Active => Result.Success(),
            MemberStatus.Disabled => Result.Failure(AuthDomainErrors.MemberDisabled),
            _ => Result.Failure(AuthDomainErrors.MemberStatusUnknown)
        };

    private Result EnsureCanDisable() =>
        this.Status switch
        {
            MemberStatus.Active => Result.Success(),
            MemberStatus.Disabled => Result.Failure(AuthDomainErrors.MemberAlreadyDisabled),
            _ => Result.Failure(AuthDomainErrors.MemberStatusUnknown)
        };

    private Result EnsureCanEnable() =>
        this.Status switch
        {
            MemberStatus.Disabled => Result.Success(),
            MemberStatus.Active => Result.Failure(AuthDomainErrors.MemberAlreadyActive),
            _ => Result.Failure(AuthDomainErrors.MemberStatusUnknown)
        };

    private Result EnsureKnownStatus() =>
        this.Status is MemberStatus.Active or MemberStatus.Disabled
            ? Result.Success()
            : Result.Failure(AuthDomainErrors.MemberStatusUnknown);

    private void Touch() => this.ConcurrencyStamp = Guid.CreateVersion7();

    private static Result<Member> CreateCore(
        MemberId id,
        string scopeId,
        string? passwordHash,
        DateTimeOffset registeredAtUtc)
    {
        if (id.Value == Guid.Empty)
        {
            return Result.Failure<Member>(AuthDomainErrors.MemberIdRequired);
        }

        if (string.IsNullOrWhiteSpace(scopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantRequired);
        }

        if (!ScopeIds.TryNormalize(scopeId, out string? normalizedScopeId))
        {
            return Result.Failure<Member>(AuthDomainErrors.TenantInvalid);
        }

        return Result.Success(new Member(id, normalizedScopeId, passwordHash)
        {
            RegisteredAtUtc = registeredAtUtc,
            ConcurrencyStamp = Guid.CreateVersion7()
        });
    }
}
