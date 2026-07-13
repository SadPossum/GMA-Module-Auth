namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Naming;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed class AuthMemberContactReader(AuthDbContext dbContext) : IAuthMemberContactReader
{
    public async ValueTask<string?> GetPreferredVerifiedEmailAsync(
        string scopeId,
        Guid memberId,
        CancellationToken cancellationToken = default)
    {
        string normalizedScopeId = ScopeIds.Normalize(scopeId, nameof(scopeId));
        MemberId id = new(memberId);
        return await dbContext.MemberUsernames
            .IgnoreQueryFilters()
            .AsNoTracking()
            .Where(username =>
                username.ScopeId == normalizedScopeId &&
                username.MemberId == id &&
                username.UsernameType == MemberUsernameType.Email &&
                username.IsActive &&
                username.VerifiedAtUtc != null)
            .Select(username => username.Value)
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
    }
}
