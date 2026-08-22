namespace Gma.Modules.Auth.Domain.Aggregates;

using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Events;
using Gma.Modules.Auth.Domain.ValueObjects;

public sealed partial class Member
{
    public Result<MemberSession> StartSession(
        MemberSessionId sessionId,
        string refreshTokenHash,
        DateTimeOffset refreshTokenExpiresAtUtc,
        DateTimeOffset nowUtc,
        string authenticationMethod = MemberAuthenticationMethods.Password,
        SessionAuthenticationEvidence? authenticationEvidence = null,
        int maximumActiveSessions = int.MaxValue,
        DateTimeOffset? absoluteExpiresAtUtc = null)
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
            absoluteExpiresAtUtc ?? refreshTokenExpiresAtUtc,
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
        => this.RefreshSessionCore(
            sessionId,
            refreshTokenHashes,
            newRefreshTokenHash,
            newRefreshTokenExpiresAtUtc,
            newAbsoluteExpiresAtUtc: null,
            authenticationEvidence: null,
            refreshTokenReusedEventId: null,
            nowUtc);

    public Result<MemberSession> RefreshSession(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        Guid refreshTokenReusedEventId,
        DateTimeOffset nowUtc)
    {
        if (refreshTokenReusedEventId == Guid.Empty)
        {
            return Result.Failure<MemberSession>(AuthDomainErrors.DomainEventIdRequired);
        }

        return this.RefreshSessionCore(
            sessionId,
            refreshTokenHashes,
            newRefreshTokenHash,
            newRefreshTokenExpiresAtUtc,
            newAbsoluteExpiresAtUtc: null,
            authenticationEvidence: null,
            refreshTokenReusedEventId,
            nowUtc);
    }

    private Result<MemberSession> RefreshSessionCore(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        DateTimeOffset? newAbsoluteExpiresAtUtc,
        SessionAuthenticationEvidence? authenticationEvidence,
        Guid? refreshTokenReusedEventId,
        DateTimeOffset nowUtc)
    {
        Result<MemberSession> result = this.RotateSessionRefreshToken(
            sessionId,
            refreshTokenHashes,
            newRefreshTokenHash,
            newRefreshTokenExpiresAtUtc,
            newAbsoluteExpiresAtUtc,
            authenticationEvidence,
            refreshTokenReusedEventId,
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
        DateTimeOffset newAbsoluteExpiresAtUtc,
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
            newAbsoluteExpiresAtUtc,
            authenticationEvidence,
            reauthenticatedEventId,
            nowUtc);
        if (result.IsFailure)
        {
            return result;
        }

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

    public Result<MemberSession> VerifySessionRefreshTokenAndHandleReuse(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        Guid refreshTokenReusedEventId,
        DateTimeOffset nowUtc)
    {
        if (refreshTokenReusedEventId == Guid.Empty)
        {
            return Result.Failure<MemberSession>(AuthDomainErrors.DomainEventIdRequired);
        }

        return this.VerifySessionRefreshTokenCore(
            sessionId,
            refreshTokenHashes,
            refreshTokenReusedEventId,
            nowUtc);
    }

    private Result<MemberSession> RotateSessionRefreshToken(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        string newRefreshTokenHash,
        DateTimeOffset newRefreshTokenExpiresAtUtc,
        DateTimeOffset? newAbsoluteExpiresAtUtc,
        SessionAuthenticationEvidence? authenticationEvidence,
        Guid? refreshTokenReusedEventId,
        DateTimeOffset nowUtc)
    {
        Result<MemberSession> verified = this.VerifySessionRefreshTokenCore(
            sessionId,
            refreshTokenHashes,
            refreshTokenReusedEventId,
            nowUtc);
        if (verified.IsFailure)
        {
            return verified;
        }

        MemberSession session = verified.Value;

        string matchingHash = refreshTokenHashes.First(session.HasRefreshTokenHash);
        Result result = authenticationEvidence is null
            ? session.Refresh(
                matchingHash,
                newRefreshTokenHash,
                newRefreshTokenExpiresAtUtc,
                nowUtc)
            : session.Reauthenticate(
                matchingHash,
                newRefreshTokenHash,
                newRefreshTokenExpiresAtUtc,
                newAbsoluteExpiresAtUtc ?? nowUtc,
                authenticationEvidence,
                nowUtc);
        return result.IsSuccess
            ? Result.Success(session)
            : Result.Failure<MemberSession>(result.Error);
    }

    private Result<MemberSession> VerifySessionRefreshTokenCore(
        MemberSessionId sessionId,
        IReadOnlyCollection<string> refreshTokenHashes,
        Guid? refreshTokenReusedEventId,
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
            MemberSession[] activeSessions = [.. this.sessions.Where(item => item.IsActive)];
            foreach (MemberSession activeSession in activeSessions)
            {
                _ = activeSession.SignOut(nowUtc);
            }

            this.Touch();
            if (refreshTokenReusedEventId is { } eventId)
            {
                this.RaiseDomainEvent(new MemberSessionsRevokedDomainEvent(
                    eventId,
                    nowUtc,
                    this.Id,
                    this.ScopeId,
                    activeSessions.Length));
            }

            return Result.Failure<MemberSession>(AuthDomainErrors.RefreshTokenReused);
        }

        MemberSession? session = this.sessions.FirstOrDefault(item =>
            item.Id == sessionId && refreshTokenHashes.Any(item.HasRefreshTokenHash));
        if (session is null)
        {
            return Result.Failure<MemberSession>(AuthDomainErrors.SessionNotFound);
        }

        return session.RefreshTokenExpiresAtUtc <= nowUtc
            ? Result.Failure<MemberSession>(AuthDomainErrors.RefreshTokenExpired)
            : Result.Success(session);
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

    public Result<int> RevokeSessions(Guid revokedEventId, DateTimeOffset nowUtc)
        => this.RevokeSessionsCore(
            session => session.IsActive,
            revokedEventId,
            nowUtc);

    public Result<int> RevokeSessionsExcept(
        MemberSessionId retainedSessionId,
        Guid revokedEventId,
        DateTimeOffset nowUtc)
    {
        if (retainedSessionId.Value == Guid.Empty)
        {
            return Result.Failure<int>(AuthDomainErrors.SessionIdRequired);
        }

        return this.RevokeSessionsCore(
            session => session.IsActive && session.Id != retainedSessionId,
            revokedEventId,
            nowUtc);
    }

    public Result<int> RevokeSessionsAuthenticatedWith(
        string authenticationMethod,
        MemberSessionId retainedSessionId,
        Guid revokedEventId,
        DateTimeOffset nowUtc)
    {
        if (!MemberAuthenticationMethods.TryNormalize(authenticationMethod, out string normalizedMethod))
        {
            return Result.Failure<int>(AuthDomainErrors.AuthenticationMethodNotValid);
        }

        if (retainedSessionId.Value == Guid.Empty)
        {
            return Result.Failure<int>(AuthDomainErrors.SessionIdRequired);
        }

        return this.RevokeSessionsCore(
            session =>
                session.IsActive &&
                session.Id != retainedSessionId &&
                string.Equals(session.AuthenticationMethod, normalizedMethod, StringComparison.Ordinal),
            revokedEventId,
            nowUtc);
    }

    private Result<int> RevokeSessionsCore(
        Func<MemberSession, bool> predicate,
        Guid revokedEventId,
        DateTimeOffset nowUtc)
    {
        if (revokedEventId == Guid.Empty)
        {
            return Result.Failure<int>(AuthDomainErrors.DomainEventIdRequired);
        }

        List<MemberSession> activeSessions = [.. this.sessions.Where(predicate)];

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
}
