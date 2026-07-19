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
            .OrderBy(member => member.RegisteredAtUtc);

        int totalCount = await dbContext.Members.CountAsync(cancellationToken).ConfigureAwait(false);
        Member[] members = await query
            .Skip(pageRequest.SkipCount)
            .Take(pageRequest.PageSize)
            .ToArrayAsync(cancellationToken)
            .ConfigureAwait(false);
        MemberId[] memberIds = [.. members.Select(member => member.Id)];
        DateTimeOffset nowUtc = clock.UtcNow;
        Dictionary<MemberId, int> activeSessionCounts = await dbContext.MemberSessions
            .AsNoTracking()
            .Where(session =>
                memberIds.Contains(session.MemberId) &&
                session.IsActive &&
                session.RefreshTokenExpiresAtUtc > nowUtc)
            .GroupBy(session => session.MemberId)
            .ToDictionaryAsync(group => group.Key, group => group.Count(), cancellationToken)
            .ConfigureAwait(false);

        AdminMemberListItem[] items = members
            .Select(member => new AdminMemberListItem(
                member.Id.Value,
                member.ScopeId,
                ToContractStatus(member.Status),
                GetActiveUsername(member),
                member.RegisteredAtUtc,
                activeSessionCounts.GetValueOrDefault(member.Id)))
            .ToArray();

        return new AdminMemberListResponse(items, pageRequest.Page, pageRequest.PageSize, totalCount);
    }

    public async Task<AdminMemberDetails?> GetMemberAsync(Guid memberId, CancellationToken cancellationToken)
    {
        Member? member = await dbContext.Members
            .AsNoTracking()
            .Include(item => item.Usernames)
            .Include(item => item.ExternalIdentities)
            .AsSplitQuery()
            .SingleOrDefaultAsync(item => item.Id == new MemberId(memberId), cancellationToken)
            .ConfigureAwait(false);

        DateTimeOffset nowUtc = clock.UtcNow;
        MemberSessionCounts? sessionCounts = member is null
            ? null
            : await dbContext.MemberSessions
                .AsNoTracking()
                .Where(session => session.MemberId == member.Id)
                .GroupBy(_ => 1)
                .Select(group => new MemberSessionCounts(
                    group.Count(session => session.IsActive && session.RefreshTokenExpiresAtUtc > nowUtc),
                    group.Count()))
                .SingleOrDefaultAsync(cancellationToken)
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
                sessionCounts?.ActiveCount ?? 0,
                sessionCounts?.TotalCount ?? 0,
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

    private static ContractMemberStatus ToContractStatus(DomainMemberStatus status) =>
        status switch
        {
            DomainMemberStatus.Active => ContractMemberStatus.Active,
            DomainMemberStatus.Disabled => ContractMemberStatus.Disabled,
            _ => ContractMemberStatus.Unknown
        };

    private sealed record MemberSessionCounts(int ActiveCount, int TotalCount);
}
