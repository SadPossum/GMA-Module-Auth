namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.EntityFrameworkCore;

internal sealed class MemberTotpAuthenticatorRepository(AuthDbContext dbContext)
    : IMemberTotpAuthenticatorRepository
{
    public Task<MemberTotpAuthenticator?> GetByMemberAsync(
        MemberId memberId,
        CancellationToken cancellationToken) =>
        dbContext.MemberTotpAuthenticators
            .Include(authenticator => authenticator.RecoveryCodes)
            .SingleOrDefaultAsync(authenticator => authenticator.MemberId == memberId, cancellationToken);

    public async Task AddAsync(MemberTotpAuthenticator authenticator, CancellationToken cancellationToken) =>
        await dbContext.MemberTotpAuthenticators.AddAsync(authenticator, cancellationToken).ConfigureAwait(false);
}
