namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed class MemberRepository(AuthDbContext dbContext, ISystemClock? clock = null) : IMemberRepository
{
    public Task<Member?> GetByIdAsync(MemberId id, CancellationToken cancellationToken) =>
        this.MembersWithActiveAuthenticationState()
            .FirstOrDefaultAsync(member => member.Id == id, cancellationToken);

    public Task<Member?> GetByUsernameAsync(string username, CancellationToken cancellationToken)
    {
        string normalizedUsername = MemberUsername.Normalize(username);

        return this.MembersWithActiveAuthenticationState()
            .FirstOrDefaultAsync(member => member.Usernames.Any(memberUsername =>
                memberUsername.IsActive && memberUsername.NormalizedValue == normalizedUsername), cancellationToken);
    }

    public Task<Member?> GetByExternalIdentityAsync(string issuer, string subject, CancellationToken cancellationToken)
    {
        string normalizedIssuer = issuer.Trim();
        string normalizedSubject = subject.Trim();
        string identityKeyHash = MemberExternalIdentity.CreateIdentityKeyHash(normalizedIssuer, normalizedSubject);
        return this.MembersWithActiveAuthenticationState()
            .FirstOrDefaultAsync(member => member.ExternalIdentities.Any(identity =>
                identity.IdentityKeyHash == identityKeyHash &&
                identity.Issuer == normalizedIssuer &&
                identity.Subject == normalizedSubject), cancellationToken);
    }

    public Task<bool> UsernameExistsAsync(string username, CancellationToken cancellationToken)
    {
        string normalizedUsername = MemberUsername.Normalize(username);

        return dbContext.MemberUsernames.AnyAsync(memberUsername =>
            memberUsername.NormalizedValue == normalizedUsername, cancellationToken);
    }

    public Task<bool> ExternalIdentityExistsAsync(string issuer, string subject, CancellationToken cancellationToken)
    {
        string normalizedIssuer = issuer.Trim();
        string normalizedSubject = subject.Trim();
        string identityKeyHash = MemberExternalIdentity.CreateIdentityKeyHash(normalizedIssuer, normalizedSubject);
        return dbContext.MemberExternalIdentities.AnyAsync(
            identity => identity.IdentityKeyHash == identityKeyHash &&
                        identity.Issuer == normalizedIssuer &&
                        identity.Subject == normalizedSubject,
            cancellationToken);
    }

    public async Task<EmailVerificationTarget?> GetByEmailVerificationTokenHashesAsync(
        IReadOnlyCollection<string> verificationTokenHashes,
        CancellationToken cancellationToken)
    {
        string[] hashes = [.. verificationTokenHashes.Distinct(StringComparer.Ordinal)];
        Member? member = await dbContext.Members
            .Include(item => item.Usernames)
            .FirstOrDefaultAsync(
                item => item.Usernames.Any(username =>
                    username.VerificationTokenHash != null && hashes.Contains(username.VerificationTokenHash)),
                cancellationToken)
            .ConfigureAwait(false);
        if (member is null)
        {
            return null;
        }

        MemberUsername username = member.Usernames.Single(item =>
            item.VerificationTokenHash is not null && hashes.Contains(item.VerificationTokenHash, StringComparer.Ordinal));
        return new EmailVerificationTarget(member, username.Id, username.VerificationTokenHash!);
    }

    public async Task AddAsync(Member member, CancellationToken cancellationToken) =>
        await dbContext.Members.AddAsync(member, cancellationToken).ConfigureAwait(false);

    private IQueryable<Member> MembersWithActiveAuthenticationState()
    {
        DateTimeOffset nowUtc = clock?.UtcNow ?? TimeProvider.System.GetUtcNow();
        return dbContext.Members
            .Include(member => member.Usernames)
            .Include(member => member.Sessions.Where(session =>
                session.IsActive &&
                session.RefreshTokenExpiresAtUtc > nowUtc &&
                session.AbsoluteExpiresAtUtc > nowUtc))
            .Include(member => member.ExternalIdentities)
            .AsSplitQuery();
    }
}
