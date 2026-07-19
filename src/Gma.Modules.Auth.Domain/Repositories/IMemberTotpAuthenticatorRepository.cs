namespace Gma.Modules.Auth.Domain.Repositories;

using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.ValueObjects;

public interface IMemberTotpAuthenticatorRepository
{
    Task<MemberTotpAuthenticator?> GetByMemberAsync(MemberId memberId, CancellationToken cancellationToken);
    Task AddAsync(MemberTotpAuthenticator authenticator, CancellationToken cancellationToken);
}
