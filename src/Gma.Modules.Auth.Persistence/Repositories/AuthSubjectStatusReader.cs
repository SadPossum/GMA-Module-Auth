namespace Gma.Modules.Auth.Persistence.Repositories;

using System.Globalization;
using Gma.Framework.Naming;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using ContractMemberStatus = Contracts.MemberStatus;
using DomainMemberStatus = Domain.Enums.MemberStatus;

internal sealed class AuthSubjectStatusReader(
    AuthDbContext dbContext,
    IAuthScopeContext scopeContext) : IAuthSubjectStatusReader
{
    public async ValueTask<AuthSubjectStatusSnapshot?> FindAsync(
        string subjectId,
        CancellationToken cancellationToken = default)
    {
        string? configuredScopeId = scopeContext.ScopeId;
        if (!scopeContext.IsEnabled ||
            !ScopeIds.TryNormalize(configuredScopeId, out string? currentScopeId) ||
            !string.Equals(currentScopeId, configuredScopeId, StringComparison.Ordinal) ||
            !dbContext.ScopeFilterEnabled ||
            !string.Equals(dbContext.CurrentScopeId, currentScopeId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Auth subject status reading requires an enabled and valid Auth scope context.");
        }

        string normalizedSubjectId = subjectId?.Trim() ?? string.Empty;
        if (!Guid.TryParse(normalizedSubjectId, out Guid memberId) || memberId == Guid.Empty)
        {
            return null;
        }

        var memberStatus = await dbContext.Members
            .AsNoTracking()
            .Where(member =>
                member.ScopeId == currentScopeId &&
                member.Id == new MemberId(memberId))
            .Select(member => new { member.ScopeId, member.Status })
            .SingleOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return memberStatus is null
            ? null
            : new AuthSubjectStatusSnapshot(
                memberStatus.ScopeId,
                memberId.ToString("D", CultureInfo.InvariantCulture),
                ToContractStatus(memberStatus.Status));
    }

    private static ContractMemberStatus ToContractStatus(DomainMemberStatus status) =>
        status switch
        {
            DomainMemberStatus.Active => ContractMemberStatus.Active,
            DomainMemberStatus.Disabled => ContractMemberStatus.Disabled,
            _ => ContractMemberStatus.Unknown
        };
}
