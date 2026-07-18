namespace Gma.Modules.Auth.Persistence.Repositories;

using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Microsoft.EntityFrameworkCore;

internal sealed class PasswordRecoveryRecipientReader(AuthDbContext dbContext)
    : IPasswordRecoveryRecipientReader
{
    public Task<PasswordRecoveryRecipient?> FindEligibleByEmailAsync(
        string email,
        CancellationToken cancellationToken)
    {
        string normalizedEmail = MemberUsername.Normalize(email);

        return (
                from username in dbContext.MemberUsernames
                join member in dbContext.Members on username.MemberId equals member.Id
                where username.NormalizedValue == normalizedEmail &&
                      username.UsernameType == MemberUsernameType.Email &&
                      username.IsActive &&
                      username.VerifiedAtUtc != null &&
                      member.Status == MemberStatus.Active &&
                      member.PasswordHash != null
                select new PasswordRecoveryRecipient(member.Id.Value, member.ScopeId, username.Value))
            .SingleOrDefaultAsync(cancellationToken);
    }
}
