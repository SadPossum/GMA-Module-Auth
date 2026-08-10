namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Naming;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using DomainMemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;

internal sealed class AuthSessionAdmissionReader(
    AuthDbContext dbContext,
    ISystemClock clock) : IAuthSessionAdmissionReader
{
    public async ValueTask<bool> IsActiveAsync(
        string scopeId,
        Guid memberId,
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        if (memberId == Guid.Empty || sessionId == Guid.Empty)
        {
            return false;
        }

        MemberId expectedMemberId = new(memberId);
        MemberSessionId expectedSessionId = new(sessionId);
        DateTimeOffset nowUtc = clock.UtcNow;

        return await dbContext.MemberSessions
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(session =>
                session.Id == expectedSessionId &&
                session.MemberId == expectedMemberId &&
                session.ScopeId == normalizedScopeId &&
                session.IsActive &&
                session.AbsoluteExpiresAtUtc > nowUtc)
            .AnyAsync(session => dbContext.Members
                .IgnoreQueryFilters()
                .Any(member =>
                    member.Id == session.MemberId &&
                    member.ScopeId == normalizedScopeId &&
                    member.Status == DomainMemberStatus.Active), cancellationToken)
            .ConfigureAwait(false);
    }
}
