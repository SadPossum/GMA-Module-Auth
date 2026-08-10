namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Naming;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using DomainMemberStatus = Gma.Modules.Auth.Domain.Enums.MemberStatus;
using DomainMemberUsernameType = Gma.Modules.Auth.Domain.Enums.MemberUsernameType;

internal sealed class AuthMemberAdmissionReader(AuthDbContext dbContext)
    : IAuthMemberAdmissionReader
{
    public async ValueTask<AuthMemberAdmission?> FindActiveAsync(
        string scopeId,
        Guid memberId,
        CancellationToken cancellationToken = default)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        MemberId id = new(memberId);

        return await dbContext.Members
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(member =>
                member.ScopeId == normalizedScopeId &&
                member.Id == id &&
                member.Status == DomainMemberStatus.Active)
            .Select(_ => new AuthMemberAdmission(
                dbContext.MemberUsernames
                    .IgnoreQueryFilters()
                    .Where(username =>
                        username.ScopeId == normalizedScopeId &&
                        username.MemberId == id &&
                        username.UsernameType == DomainMemberUsernameType.Email &&
                        username.IsActive &&
                        username.VerifiedAtUtc != null)
                    .Select(username => username.Value)
                    .SingleOrDefault()))
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
    }
}
