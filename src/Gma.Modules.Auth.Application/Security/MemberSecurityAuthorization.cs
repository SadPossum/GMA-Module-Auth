namespace Gma.Modules.Auth.Application.Security;

using Gma.Framework.Results;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;

internal static class MemberSecurityAuthorization
{
    public static Result<MemberSession> RequireFreshSession(
        Member member,
        Guid sessionId,
        DateTimeOffset nowUtc,
        TimeSpan freshness)
    {
        if (sessionId == Guid.Empty)
        {
            return Result.Failure<MemberSession>(AuthApplicationErrors.FreshAuthenticationRequired);
        }

        MemberSessionId id = new(sessionId);
        MemberSession? session = member.Sessions.FirstOrDefault(item => item.Id == id && item.IsActive);
        return session is not null && session.LoginDateTimeUtc >= nowUtc.Subtract(freshness)
            ? Result.Success(session)
            : Result.Failure<MemberSession>(AuthApplicationErrors.FreshAuthenticationRequired);
    }

    public static Result RequirePassword(
        Member member,
        string? currentPassword,
        IPasswordHashingService passwordHashingService)
    {
        if (member.PasswordHash is null || string.IsNullOrEmpty(currentPassword))
        {
            return Result.Failure(AuthApplicationErrors.CredentialsNotValid);
        }

        PasswordVerificationOutcome outcome = passwordHashingService.VerifyPassword(
            member.PasswordHash,
            currentPassword);
        return outcome is PasswordVerificationOutcome.Success or PasswordVerificationOutcome.SuccessRehashNeeded
            ? Result.Success()
            : Result.Failure(AuthApplicationErrors.CredentialsNotValid);
    }
}
