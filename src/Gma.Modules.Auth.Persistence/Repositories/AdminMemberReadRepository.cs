namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Pagination;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;
using ContractMemberStatus = Contracts.MemberStatus;
using DomainMemberStatus = Domain.Enums.MemberStatus;

internal sealed class AdminMemberReadRepository(AuthDbContext dbContext, ISystemClock clock) : IAdminMemberReadRepository
{
    public async Task<AdminMemberListResponse> ListMembersAsync(
        PageRequest pageRequest,
        CancellationToken cancellationToken)
    {
        IQueryable<Member> query = dbContext.Members
            .AsNoTracking()
            .Include(member => member.Usernames)
            .Include(member => member.Sessions)
            .AsSplitQuery()
            .OrderBy(member => member.RegisteredAtUtc);

        int totalCount = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        Member[] members = await query
            .Skip(pageRequest.SkipCount)
            .Take(pageRequest.PageSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);

        AdminMemberListItem[] items = members
            .Select(member => new AdminMemberListItem(
                member.Id.Value,
                member.ScopeId,
                ToContractStatus(member.Status),
                GetActiveUsername(member),
                member.RegisteredAtUtc,
                CountActiveSessions(member, clock.UtcNow)))
            .ToArray();

        return new AdminMemberListResponse(items, pageRequest.Page, pageRequest.PageSize, totalCount);
    }

    public async Task<AdminMemberDetails?> GetMemberAsync(Guid memberId, CancellationToken cancellationToken)
    {
        Member? member = await dbContext.Members
            .AsNoTracking()
            .Include(item => item.Usernames)
            .Include(item => item.Sessions)
            .Include(item => item.ExternalIdentities)
            .AsSplitQuery()
            .SingleOrDefaultAsync(item => item.Id == new MemberId(memberId), cancellationToken)
            .ConfigureAwait(false);

        MemberTotpAuthenticator? authenticator = member is null
            ? null
            : await dbContext.MemberTotpAuthenticators
                .AsNoTracking()
                .Include(item => item.RecoveryCodes)
                .SingleOrDefaultAsync(item => item.MemberId == member.Id, cancellationToken)
                .ConfigureAwait(false);

        return member is null
            ? null
            : new AdminMemberDetails(
                member.Id.Value,
                member.ScopeId,
                ToContractStatus(member.Status),
                GetActiveUsername(member),
                member.RegisteredAtUtc,
                member.DisabledAtUtc,
                member.DisabledReason,
                CountActiveSessions(member, clock.UtcNow),
                member.Sessions.Count,
                member.HasPassword,
                member.Usernames.Any(username => username.IsActive && username.IsVerified),
                member.ExternalIdentities
                    .Select(identity => identity.ProviderCode)
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray(),
                authenticator?.IsActive == true,
                authenticator?.UnusedRecoveryCodeCount ?? 0,
                authenticator?.ActivatedAtUtc);
    }

    private static string? GetActiveUsername(Member member) =>
        member.Usernames
            .Where(username => username.IsActive)
            .OrderBy(username => username.UsernameType)
            .Select(username => username.Value)
            .FirstOrDefault();

    private static int CountActiveSessions(Member member, DateTimeOffset nowUtc) =>
        member.Sessions.Count(session => session.IsActive && session.RefreshTokenExpiresAtUtc > nowUtc);

    private static ContractMemberStatus ToContractStatus(DomainMemberStatus status) =>
        status switch
        {
            DomainMemberStatus.Active => ContractMemberStatus.Active,
            DomainMemberStatus.Disabled => ContractMemberStatus.Disabled,
            _ => ContractMemberStatus.Unknown
        };
}
